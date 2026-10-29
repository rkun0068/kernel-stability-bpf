# reclaimlat

Traces Direct Reclaim latency: how long each task stalls in the allocator's
direct reclaim path, and how many pages it got back.

## Usage

```bash
sudo ./build/reclaimlat              # every direct reclaim + histogram on exit
sudo ./build/reclaimlat -m 10000     # only reclaims >= 10 ms
sudo ./build/reclaimlat -p 1234 -d 60
sudo ./build/reclaimlat -H -d 30     # histogram only (lowest overhead)
```

Sample output:

```
TIME     TGID    PID     COMM             ORDER GFP        NR_RECLAIMED   LAT(ms)
14:02:11 4123    4127    java             0     0x140cca   32               12.481
```

## Design

| Item | Value |
|------|-------|
| Hooks | `tracepoint:vmscan:mm_vmscan_direct_reclaim_begin` / `_end` |
| Maps | `start` (hash, pid → ts), `events` (perf buffer), `hist` (array, log2 µs) |
| Requires | kernel ≥ 5.4, no BTF. Perf buffer instead of ringbuf so it loads before 5.8 |
| Overhead | Two tracepoint hits per reclaim; reclaim is already a slow path |

## Known limitations

- Only global direct reclaim. Memcg reclaim (`mm_vmscan_memcg_reclaim_*`) is not
  traced yet — planned for v0.2.
- If the tool starts while a task is mid-reclaim, that reclaim is missed.

## Roadmap

| Version | Goal |
|---------|------|
| v0.1 | Per-event PID/COMM/latency + histogram (this) |
| v0.2 | Memcg reclaim, per-cgroup breakdown |
| v0.3 | Correlate with memory PSI |
| v0.4 | NUMA node / watermark context |
| v0.5 | Kernel stacks for long-tail reclaims |
