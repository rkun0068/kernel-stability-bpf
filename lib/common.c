// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>
#include "common.h"

static void print_stars(uint32_t val, uint32_t max, int width)
{
	int n = max ? (int)((uint64_t)val * width / max) : 0;
	int i;

	for (i = 0; i < n && i < width; i++)
		putchar('*');
	if (val > max)
		putchar('+');
}

void print_log2_hist(const uint32_t *vals, int nr, const char *unit)
{
	int i, last = -1;
	uint32_t max = 0;

	for (i = 0; i < nr; i++) {
		if (vals[i] > 0)
			last = i;
		if (vals[i] > max)
			max = vals[i];
	}
	if (last < 0) {
		printf("(no samples)\n");
		return;
	}

	printf("%*s%-*s : count    distribution\n", 10, "", 14, unit);
	for (i = 0; i <= last; i++) {
		uint64_t low = i ? (1ULL << i) : 0;
		uint64_t high = (1ULL << (i + 1)) - 1;

		printf("%10llu -> %-10llu : %-8u |", (unsigned long long)low,
		       (unsigned long long)high, vals[i]);
		print_stars(vals[i], max, 40);
		printf("%*s|\n", max ? 40 - (int)((uint64_t)vals[i] * 40 / max) : 40, "");
	}
}

int bump_memlock_rlimit(void)
{
	struct rlimit r = { RLIM_INFINITY, RLIM_INFINITY };

	return setrlimit(RLIMIT_MEMLOCK, &r);
}

void fmt_now(char *buf, int len)
{
	time_t t = time(NULL);
	struct tm tm;

	localtime_r(&t, &tm);
	strftime(buf, len, "%H:%M:%S", &tm);
}
