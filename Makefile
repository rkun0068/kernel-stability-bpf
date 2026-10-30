# SPDX-License-Identifier: GPL-2.0
# Build all tools: make
# Build one tool:  make reclaimlat
# Requires: clang, bpftool, libbpf-devel (>= 0.5), libelf, zlib. No kernel BTF needed.

OUTPUT    := build
CLANG     ?= clang
BPFTOOL   ?= bpftool
CC        ?= cc

ARCH := $(shell uname -m | sed -e 's/x86_64/x86/' -e 's/aarch64/arm64/' \
		-e 's/ppc64le/powerpc/' -e 's/s390x/s390/' -e 's/riscv64/riscv/')

LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf 2>/dev/null)
LIBBPF_LIBS   := $(shell pkg-config --libs libbpf 2>/dev/null || echo -lbpf) -lelf -lz
# Version of the installed library, not of the headers: some hosts carry stray
# libbpf_version.h files from other libbpf installs.
LIBBPF_MAJOR  := $(or $(shell pkg-config --modversion libbpf 2>/dev/null | cut -d. -f1),1)

INCLUDES  := -I$(OUTPUT) -Iinclude $(LIBBPF_CFLAGS)
# Debian/Ubuntu keep asm/types.h under the multiarch dir
BPF_INCLUDES := $(INCLUDES) -I/usr/include/$(shell uname -m)-linux-gnu
CFLAGS    ?= -g -O2 -Wall
CFLAGS    += -DLIBBPF_MAJOR=$(LIBBPF_MAJOR)
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)

# tool name -> source directory
TOOLS := reclaimlat numawatch numaguard
reclaimlat_DIR := tools/memory/reclaimlat
numawatch_DIR  := tools/memory/numawatch
numaguard_DIR  := tools/memory/numaguard

COMMON_OBJS := $(OUTPUT)/common.o

.PHONY: all clean install-numaguard $(TOOLS)
all: $(TOOLS)

$(TOOLS): %: $(OUTPUT)/%

$(OUTPUT):
	mkdir -p $@

$(OUTPUT)/common.o: lib/common.c include/common.h | $(OUTPUT)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

.SECONDEXPANSION:

$(OUTPUT)/%.bpf.o: $$($$*_DIR)/%.bpf.c $$(wildcard $$($$*_DIR)/*.h) include/tp_vmscan.h | $(OUTPUT)
	$(CLANG) $(BPF_CFLAGS) $(BPF_INCLUDES) -I$($*_DIR) -c $< -o $@

$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

$(OUTPUT)/%.o: $$($$*_DIR)/%.c $(OUTPUT)/%.skel.h $$(wildcard $$($$*_DIR)/*.h)
	$(CC) $(CFLAGS) $(INCLUDES) -I$($*_DIR) -c $< -o $@

$(OUTPUT)/%: $(OUTPUT)/%.o $(COMMON_OBJS)
	$(CC) $(CFLAGS) $^ $(LIBBPF_LIBS) -o $@

install-numaguard: numaguard
	install -m 0755 $(OUTPUT)/numaguard /usr/local/sbin/numaguard
	install -m 0644 $(numaguard_DIR)/numaguard.service /etc/systemd/system/numaguard.service
	systemctl daemon-reload

clean:
	rm -rf $(OUTPUT)
