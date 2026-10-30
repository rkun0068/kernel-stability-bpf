# numaguard

Daemon that detects the NUMA-node thrashing that precedes a host hang
(no swap, kernel never OOMs, IO PSI full ~90%) and tells the NodeManager
which node is thrashing. It only decides; killing containers is NM's job.

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
state=kill nodes=1 since=1761000000
```

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
`OOMScoreAdjust=-1000` and `Nice=-10`. It uses no BPF (so no JIT dependency)
and reads a few procfs/sysfs files per second.
