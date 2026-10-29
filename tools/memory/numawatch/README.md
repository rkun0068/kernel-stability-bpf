# numawatch

Per-NUMA-node memory distribution and reclaim activity, reported every interval.
Built for after-the-fact debugging: run it long-term with `-j` and read the
JSON Lines next to sar/atop data for the same time window.

## Usage

```bash
sudo ./build/numawatch                 # table every 10s
sudo ./build/numawatch -i 30 -j >> /var/log/numawatch.jsonl
sudo ./build/numawatch -i 5 -d 60
```

Sample table:

```
14:02:20 NODE  FREE(MB)   LOW(MB)  FILE(MB)   MISS/s  KSWAKE KSW(ms)    DIRECT  D_MAX  NODE_RCL  N_MAX   SCANNED  EFF%  FLAGS
         0          212       180      1043    840.2     311    4210        57   48.3         0    0.0    912034     7  BELOW_LOW,IMBALANCE,HIGH_MISS,LOW_EFFICIENCY
         1        48211       182     20113      0.0       0       0         0    0.0         0    0.0         0   100  -
```

## Columns

| Column | Source | Meaning |
|--------|--------|---------|
| FREE / LOW / FILE | `nodeN/meminfo`, `/proc/zoneinfo` | Free memory, low watermark, page cache |
| MISS/s | `nodeN/numastat` | Allocations meant for this node that landed elsewhere |
| KSWAKE | `mm_vmscan_wakeup_kswapd` | Allocations that woke this node's kswapd |
| KSW(ms) | `mm_vmscan_kswapd_wake/sleep` | Time kswapd was awake in the interval |
| DIRECT / D_MAX | `mm_vmscan_direct_reclaim_*` | Direct reclaims on this node's CPUs, worst latency (ms) |
| NODE_RCL / N_MAX | `mm_vmscan_node_reclaim_*` | `zone_reclaim_mode` reclaims, worst latency (ms) |
| SCANNED / EFF% | `mm_vmscan_lru_shrink_inactive` | Inactive LRU pages scanned, % reclaimed |

## Flags

| Flag | Condition | What it usually means |
|------|-----------|-----------------------|
| `BELOW_MIN` / `BELOW_LOW` | free ≤ min / low watermark | Node is under hard pressure |
| `IMBALANCE` | free ≤ high watermark while another node has > 20% free | Workload pinned to one node (cpuset, `numactl --membind`, MPOL_BIND) |
| `NODE_RECLAIM` | any node_reclaim in the interval | `zone_reclaim_mode != 0` reclaiming locally instead of falling back to a remote node |
| `HIGH_MISS` | numa_miss > 10% of allocations | Heavy remote allocation, latency for memory-bound apps |
| `LOW_EFFICIENCY` | reclaimed < 10% of scanned | Scanning hard but freeing little, often thrashing |

## Design

| Item | Value |
|------|-------|
| Hooks | vmscan tracepoints only (no kprobes) |
| Maps | `stats` per-CPU array by node (no atomics), cleared every interval |
| Requires | BTF, kernel ≥ 5.8. node_reclaim hooks auto-skip if absent |
| Overhead | Counter updates only; no per-event output |

## Known limitations

- Direct reclaim is attributed to the node of the CPU where it started, not the
  node being reclaimed.
- `IMBALANCE` and the other thresholds are fixed for now.
- Does not track NUMA balancing migrations yet (planned).
