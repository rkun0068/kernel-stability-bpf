CC ?= gcc

all: numasnap test/snapkill

numasnap: numasnap.c
	$(CC) -O2 -Wall -o $@ $<

test/snapkill: test/snapkill.c
	$(CC) -O2 -Wall -o $@ $<

clean:
	rm -f numasnap test/snapkill

.PHONY: all clean
