# SPDX-License-Identifier: GPL-2.0
# Build all tools: make
# Build one tool:  make reclaimlat
# Requires: clang, bpftool, libbpf-dev (>= 1.0), libelf, zlib, a kernel with BTF.

OUTPUT    := build
CLANG     ?= clang
BPFTOOL   ?= bpftool
CC        ?= cc
VMLINUX   ?= /sys/kernel/btf/vmlinux

ARCH := $(shell uname -m | sed -e 's/x86_64/x86/' -e 's/aarch64/arm64/' \
		-e 's/ppc64le/powerpc/' -e 's/s390x/s390/' -e 's/riscv64/riscv/')

LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf 2>/dev/null)
LIBBPF_LIBS   := $(shell pkg-config --libs libbpf 2>/dev/null || echo -lbpf) -lelf -lz

INCLUDES  := -I$(OUTPUT) -Iinclude $(LIBBPF_CFLAGS)
CFLAGS    ?= -g -O2 -Wall
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)

# tool name -> source directory
TOOLS := reclaimlat numawatch
reclaimlat_DIR := tools/memory/reclaimlat
numawatch_DIR  := tools/memory/numawatch

COMMON_OBJS := $(OUTPUT)/common.o

.PHONY: all clean $(TOOLS)
all: $(TOOLS)

$(TOOLS): %: $(OUTPUT)/%

$(OUTPUT):
	mkdir -p $@

$(OUTPUT)/vmlinux.h: | $(OUTPUT)
	$(BPFTOOL) btf dump file $(VMLINUX) format c > $@

$(OUTPUT)/common.o: lib/common.c include/common.h | $(OUTPUT)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

.SECONDEXPANSION:

$(OUTPUT)/%.bpf.o: $$($$*_DIR)/%.bpf.c $$(wildcard $$($$*_DIR)/*.h) $(OUTPUT)/vmlinux.h
	$(CLANG) $(BPF_CFLAGS) $(INCLUDES) -I$($*_DIR) -c $< -o $@
	$(BPFTOOL) gen object $@.tmp $@ && mv $@.tmp $@

$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

$(OUTPUT)/%.o: $$($$*_DIR)/%.c $(OUTPUT)/%.skel.h $$(wildcard $$($$*_DIR)/*.h)
	$(CC) $(CFLAGS) $(INCLUDES) -I$($*_DIR) -c $< -o $@

$(OUTPUT)/%: $(OUTPUT)/%.o $(COMMON_OBJS)
	$(CC) $(CFLAGS) $^ $(LIBBPF_LIBS) -o $@

clean:
	rm -rf $(OUTPUT)
