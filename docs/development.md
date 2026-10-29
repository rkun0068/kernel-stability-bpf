# Development guide

## Environment

Use a Linux KVM VM (not a production host) for stress experiments. Ubuntu 22.04+
or RHEL 9 ship BTF-enabled kernels. macOS cannot build or load BPF programs.

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
