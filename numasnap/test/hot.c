// SPDX-License-Identifier: GPL-2.0
/*
 * hot: stand-in for JVM code pages. THREADS threads keep touching random
 * pages in the first HOT_MB of FILEs, mapped PROT_READ|PROT_EXEC and shared
 * by every process that maps them. Pages are touched far more often than
 * reclaim can scan them, so reclaim finds them referenced and keeps them:
 * it scans a lot and frees little, and what it does free faults back in.
 *
 * usage: hot HOT_MB THREADS FILE...
 */
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>

static char *map[64];
static unsigned long per, npages;

static void *touch(void *arg)
{
	unsigned long x = (unsigned long)arg * 2654435761UL + 1;
	volatile char sink;

	for (;;) {
		unsigned long i;

		x ^= x << 13, x ^= x >> 7, x ^= x << 17;	/* xorshift */
		i = x % npages;
		sink = map[i / per][i % per * 4096];
	}
	return (void *)(long)sink;
}

int main(int argc, char **argv)
{
	int i, nfile = argc - 3, threads;
	pthread_t t;
	struct stat st;

	if (argc < 4 || nfile > 64)
		return 2;
	npages = strtoul(argv[1], NULL, 10) * 256;
	threads = atoi(argv[2]);
	for (i = 0; i < nfile; i++) {
		int fd = open(argv[3 + i], O_RDONLY);

		if (fd < 0 || fstat(fd, &st))
			return 1;
		map[i] = mmap(NULL, st.st_size, PROT_READ | PROT_EXEC, MAP_SHARED, fd, 0);
		if (map[i] == MAP_FAILED)
			return 1;
		madvise(map[i], st.st_size, MADV_RANDOM);	/* fault one page at a time, like code */
	}
	per = st.st_size / 4096;
	if (npages > per * nfile)
		npages = per * nfile;
	for (i = 1; i < threads; i++)
		pthread_create(&t, NULL, touch, (void *)(long)i);
	touch(0);
	return 0;
}
