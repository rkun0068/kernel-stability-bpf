/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NUMAGUARD_H
#define __NUMAGUARD_H

#define MAX_NODES 8

/* pages allocated by one cgroup on one NUMA node */
struct alloc_key {
	__u64 cgid;
	__u32 nid;
	__u32 pad;	/* the 5.4 verifier rejects uninitialized padding */
};

#endif
