/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KSB_COMMON_H
#define __KSB_COMMON_H

#include <stdbool.h>
#include <stdint.h>

#define MAX_SLOTS 27

/* Print a log2 histogram. `unit` is the label for the value column, e.g. "usecs". */
void print_log2_hist(const uint32_t *vals, int nr, const char *unit);

/* Bump RLIMIT_MEMLOCK for kernels < 5.11 that still account BPF memory there. */
int bump_memlock_rlimit(void);

/* Format current wall-clock time as HH:MM:SS into buf. */
void fmt_now(char *buf, int len);

#endif
