# Development guide

## Environment

Use a Linux test host (not a production host) for stress experiments. macOS
cannot build or load BPF programs.

## No-BTF kernels

The production kernel (elrepo kernel-lt 5.4) has no BTF, so the tools do not
use `vmlinux.h` or CO-RE. Tracepoint context structs are written by hand in
`include/tp_vmscan.h` from the kernel's format files:

```bash
sudo cat /sys/kernel/debug/tracing/events/vmscan/mm_vmscan_kswapd_wake/format
```

When adding a hook, copy its fields (respecting the offsets) into a header the
same way. Avoid ringbuf (needs 5.8); use a perf event array.

## Adding a tool

1. Create `tools/<area>/<name>/` with `<name>.bpf.c`, `<name>.c`, `<name>.h`, `README.md`.
2. In the top-level `Makefile`, append `<name>` to `TOOLS` and add
   `<name>_DIR := tools/<area>/<name>`.
3. `make <name>` generates `build/<name>.skel.h` and the binary `build/<name>`.

## Per-tool README checklist

Every tool must document:

- Hooks used (tracepoint / kprobe / fentry) and why
- Minimum kernel version and BTF dependency
- Measured overhead under load
- Known limitations

Prefer tracepoints and `tp_btf` over kprobes: kprobed functions get inlined or
renamed across kernel versions, which is the main reason a tool works on the
dev box and fails on the target.

## Reproducing memory pressure

```bash
stress-ng --vm 4 --vm-bytes 95% --timeout 60s
```

## Licensing

When adapting code from BCC, bpftrace or libbpf-bootstrap, keep the original
SPDX header and copyright lines, and check license compatibility with GPL-2.0.
