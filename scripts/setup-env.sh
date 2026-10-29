#!/usr/bin/env bash
# Install build dependencies on Ubuntu/Debian or RHEL/Fedora.
set -euo pipefail

if command -v apt-get >/dev/null; then
	sudo apt-get update
	sudo apt-get install -y clang llvm make pkg-config libbpf-dev libelf-dev zlib1g-dev \
		linux-tools-common "linux-tools-$(uname -r)" || sudo apt-get install -y bpftool
elif command -v dnf >/dev/null; then
	sudo dnf install -y clang llvm make pkgconf libbpf-devel elfutils-libelf-devel zlib-devel bpftool
else
	echo "unsupported distro; install clang, bpftool, libbpf-dev, libelf, zlib manually" >&2
	exit 1
fi

if [ ! -r /sys/kernel/btf/vmlinux ]; then
	echo "warning: /sys/kernel/btf/vmlinux missing; kernel lacks CONFIG_DEBUG_INFO_BTF" >&2
fi
