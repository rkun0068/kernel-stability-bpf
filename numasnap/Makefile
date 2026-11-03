CLANG ?= clang
CC    ?= gcc

all: numasnap numasnap.bpf.o test/snapkill

numasnap.bpf.o: numasnap.bpf.c numasnap.h
	$(CLANG) -O2 -g -target bpf -c $< -o $@

# shared libraries are fine: mlockall() at startup locks them in memory too
numasnap: numasnap.c numasnap.h
	$(CC) -O2 -Wall -o $@ $< -lbpf -lelf -lz

test/snapkill: test/snapkill.c
	$(CC) -O2 -Wall -o $@ $<

clean:
	rm -f numasnap numasnap.bpf.o test/snapkill

.PHONY: all clean
