# numaguard

Daemon that detects the NUMA-node thrashing that precedes a host hang
(no swap, kernel never OOMs, IO PSI full ~90%) and tells the NodeManager
which node is thrashing and which containers are filling it. It only decides;
killing containers is NM's job.

## Rules

Checked every second. Thresholds are constants at the top of `numaguard.c`.

| Verdict | Condition | Held for |
|---------|-----------|----------|
| `warn` | a node's kswapd CPU < 1% **and** its free memory < high watermark | 10 min |
| `kill` | host: IO PSI full avg10 ≥ 80 **and** iowait ≥ 80% **and** scan ≥ 600k pages/s **and** reclaimed ≤ 10% of scanned;<br>node: page cache < 1G **and** free < high + 1G | 60 s |

A `kill` verdict is kept for at least 5 minutes so NM has time to act.
Sources are the ones the thresholds came from: scan and reclaim are host-wide
`/proc/vmstat` (sar -B), kswapd CPU is `/proc/<kswapdN>/stat` (atop PRC).
The node whose kswapd stopped still has page cache, so it does not reach `kill`.

## Output

`/run/numaguard/state` (tmpfs, replaced atomically):

```
state=kill nodes=1 culprits=container_..._000826(queue=adhoc,low,node=9800M),container_..._001015(queue=szsc-prod,high,node=21000M) since=1761000000
```

`culprits` are up to 3 containers under `/sys/fs/cgroup/yarn`, in kill order:

1. **On the thrashing node**: it allocated pages there since tracing started.
2. **Large share of the node**: it holds ≥ 5% of the node's memory, estimated
   as `memory.current` × (its pages allocated on the node / all its pages).
   5.4 has no per-node memory per cgroup; using `memory.current` keeps
   page-cache churn (shuffle writes) from looking big.
3. **Low priority first**, then the most memory on the node. Priority comes
   from `spark.yarn.queue` in the container's
   `__spark_conf__/__spark_conf__.properties` (only that key is read):
   queues ending in `-prod` are high priority.

Each entry reads `name(queue=...,low|high,node=<MB>)`. Ranked once, when the
kill verdict starts. A container that filled its memory before tracing started
and has been idle since is not a candidate.

## Finding culprits (BPF)

Containers are not bound to nodes, and 5.4 has no `memory.numa_stat`, so the
only cheap way to know who fills a node is to watch page allocations:
`kmem:mm_page_alloc` → key `cgroup id << 8 | node` (node from pfn) → pages.
Page allocation is a hot path and the hosts run without BPF JIT, so the program
is loaded only while a node is in `warn` or is counting towards `kill`, and
unloaded when everything is `ok` again. If BPF fails to load, the verdicts still
work and `culprits` stays empty.

Counts are gross allocations (frees are not subtracted), which is why they
only split a container's `memory.current` across nodes.

`/run/numaguard/events.log`: one line with all metrics each time the verdict changes.

## Dry run

By default a `kill` verdict is written as `state=warn` and only logged with
`dry_run=1`. Run with `--enforce` (edit `ExecStart`) once the thresholds are
validated against normal nights: IO PSI full, iowait and page cache still
have no baseline.

## Install

```bash
make install-numaguard
systemctl enable --now numaguard
cat /run/numaguard/state
```

## Self-protection

The guard must keep working while the host thrashes: it `mlockall()`s itself,
allocates nothing in the loop, writes only to `/run`, and runs with
`OOMScoreAdjust=-1000` and `Nice=-10`. Normally it only reads a few procfs/sysfs
files per second; the BPF program runs only around an incident.
