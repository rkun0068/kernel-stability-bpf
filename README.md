# kernel-stability-bpf

eBPF-based Linux kernel stability observability toolkit (libbpf + CO-RE),
focused on memory, block I/O, network and scheduler anomalies.

## Tools

| Area | Tool | Status | Purpose |
|------|------|--------|---------|
| Memory | [reclaimlat](tools/memory/reclaimlat) | v0.1 | Direct reclaim latency |
| Memory | alloclat | planned | Allocation slow path |
| Memory | [numawatch](tools/memory/numawatch) | v0.1 | Per-node memory and reclaim anomalies |
| Memory | [numaguard](tools/memory/numaguard) | v0.1 | systemd daemon: flags the NUMA node that is thrashing |
| Disk | biolat | planned | Block I/O latency |
| Disk | writebacklat | planned | Writeback latency |
| Network | tcpwatch | planned | TCP retransmits / anomalies |
| Scheduler | runqlat | planned | Run queue latency |

## Build

Linux only, kernel ≥ 5.4. Kernel BTF is not required: tracepoint layouts
live in [include/tp_vmscan.h](include/tp_vmscan.h). Verified target:
5.4.139-1.el7.elrepo (kernel-lt), libbpf 0.5, bpftool 5.10.

```bash
./scripts/setup-env.sh   # install clang, bpftool, libbpf-dev
make
sudo ./build/reclaimlat
```

## Layout

```
tools/<area>/<tool>/   <tool>.bpf.c (kernel), <tool>.c (loader), README.md
include/, lib/         shared helpers (histograms, rlimit, time)
docs/                  architecture and development guide
```

See [docs/development.md](docs/development.md) for adding a new tool.

## License

GPL-2.0. BPF programs declare `SEC("license") = "GPL"`.
