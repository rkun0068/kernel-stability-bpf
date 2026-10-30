# Design: a rule-driven guard daemon

Status: proposal. Today `numaguard` hard-codes two rules (W and K) for the
NUMA-node hang. This document turns it into a general engine: operators write
rules and scripts, and the engine does the collection, eBPF, and timing.

## Goals

- Operators add a scenario by dropping in a rule file, not by changing C code.
- Operators write bash or python, never eBPF.
- Detection keeps working while the host is stalled on IO and memory.
- The engine stays small enough to read in one sitting.

## Non-goals

- Replacing atop, sar, or the kernel OOM killer.
- A general expression language. Rules are a list of comparisons.
- Killing containers directly. The NodeManager does that.

## Layers

```
user      rules.d/*.rules     condition -> action, declarative
          actions/*.sh|*.py   run when a rule fires
          checks/*.sh|*.py    optional, for logic a rule can't express
-------------------------------------------------------------------
interface /run/guard/metrics.json   one snapshot per second
          guardctl get|watch         for bash
          import guard               for python
-------------------------------------------------------------------
engine    collectors   procfs, sysfs, PSI, vmstat
          probes       prebuilt eBPF programs, loaded on demand
          evaluator    rules, durations, cooldown, dry run
```

## Metrics

Collected every second by the engine, with no fork and no disk reads.

| Scope | Metrics |
|---|---|
| host | `psi.{cpu,mem,io}.{some,full}`, `iowait`, `scan` (pages/s), `eff` (reclaim efficiency %) |
| node | `free`, `file`, `high`, `free_over_high`, `kswapd` (CPU %) |
| cgroup | `mem`, `psi.mem.full`, and probe fields such as `node_share` |

Derived metrics (such as `free_over_high`) replace arithmetic in rules.

## Probes

eBPF programs are a fixed catalog, written once for the oldest supported
kernel (5.4: no BTF, no ringbuf, JIT off). The engine loads a probe only while
an active rule or action needs one of its fields, and unloads it afterwards.

| Probe | Fields | Use |
|---|---|---|
| `cgroup_node_alloc` | pages each cgroup allocated on each node | culprits on a thrashing node |
| `direct_reclaim` | direct reclaim count and latency per cgroup | who is stuck in reclaim |
| `io_latency` | IO latency per cgroup | who drives or waits on IO |
| `page_refault` | refaults per cgroup | direct evidence of thrash |

Only `cgroup_node_alloc` exists today. Others are added when a scenario needs
them.

## Rules

One file per scenario in `/etc/guard/rules.d/`. `systemctl reload` rereads
them; removing a file retires the scenario.

```
# spark.rules
scope   /sys/fs/cgroup/yarn
prio    file=__spark_conf__/__spark_conf__.properties key=spark.yarn.queue high=*-prod
mode    dry

rule spark_numa_thrash
  when host.psi.io.full >= 80  host.iowait >= 80  host.eff <= 10   for 60s
  when node.file < 1G  node.free_over_high < 1G
  do   kill pick=node_share,low_prio top=3 cooldown=300s

rule spark_mem_pressure
  when host.psi.mem.full >= 30   for 120s
  do   exec /etc/guard/actions/dump_spark.sh
```

- File header: `scope` is where the containers live, `prio` says how to read a
  container's priority, and `mode` is `dry` or `enforce`.
- Conditions in a rule are ANDed. Write two rules for OR.
- `for` is how long the conditions must hold. Without it, one sample is enough.
- A rule that names `node.*` is evaluated per node. The matching nodes are
  passed to the action.

## Actions

| Action | Effect |
|---|---|
| `warn` | write the state file and the event log |
| `exec <script>` | run a script with the context in `GUARD_*` environment variables, under a timeout |
| `kill pick=... top=N cooldown=Ns` | rank culprits and publish them in the state file for the NodeManager; only in `enforce` mode |

Pick strategies combine left to right: `node_share` (share of the matching
nodes), `low_prio` (low priority first), `mem` (largest first).

## Checks

A check is a script run on an interval for logic a rule can't express. It
follows the Nagios plugin convention: exit 0 for OK, 1 for warning, 2 for
critical, and the first line of stdout is the reason. A check that exceeds its
timeout counts as unknown and fires nothing.

```python
# checks/spark_skew.py
import guard
m = guard.metrics()
hot = [n for n in m.nodes if n.file < 1 << 30 and n.free_over_high < 1 << 30]
if hot and m.host.eff <= 10:
    print("spark numa skew on", [n.id for n in hot]); raise SystemExit(2)
```

## Behavior during an incident

When the host is stalled, starting python or bash can take seconds because
binaries are read from a saturated disk. So:

- Detection uses declarative rules, evaluated by the mlocked engine.
- Checks are for slow-moving conditions only.
- `kill` writes the state file from the engine and does not depend on a script.
- The engine runs with `OOMScoreAdjust=-1000`, `Nice=-10`, and `mlockall`.

## YARN integration

- **Warn**: point `yarn.nodemanager.health-checker.script.path` at a script
  that prints `ERROR <reason>` while the state is warn or kill. The
  NodeManager marks the node unhealthy and stops placing new containers on it.
- **Kill**: the NodeManager, or a sidecar, reads the culprits from the state
  file and kills them.

## Prior art

| Layer | Borrowed from |
|---|---|
| Rule syntax | Monit (`if ... for N cycles then ...`), Netdata health.d |
| Rule semantics | oomd: durations, post-action delay, dry run, drop-in rulesets |
| Checks | Nagios plugin exit codes; node-problem-detector custom plugins |
| Probes | Falco's named fields over eBPF events; Inspektor Gadget's prebuilt gadget catalog |
| Ad-hoc tracing | bpftrace, for experts on a live host |
| Recording | below, atop, sar |

## Plan

1. Engine, rules, and actions. Express today's W and K as `numa.rules`, and
   verify kill and recovery with `tests/memory/repro_hang.sh`.
2. `metrics.json` and `guardctl`.
3. The python library and more probes, when a scenario needs them.
