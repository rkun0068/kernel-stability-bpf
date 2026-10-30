/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NUMAWATCH_H
#define __NUMAWATCH_H

#define NUMA_MAX_NODES 64

/* Per-node counters, kept in a per-CPU array indexed by node id. */
struct node_stat {
	__u64 wakeup_kswapd;	/* allocations that had to wake kswapd */
	__u64 kswapd_runs;
	__u64 kswapd_ns;	/* time kswapd spent awake */
	__u64 direct_cnt;	/* direct reclaims started on a CPU of this node */
	__u64 direct_ns;
	__u64 direct_max_ns;
	__u64 nrcl_cnt;		/* node_reclaim (zone_reclaim_mode) on this node */
	__u64 nrcl_ns;
	__u64 nrcl_max_ns;
	__u64 scanned;		/* inactive LRU pages scanned on this node */
	__u64 reclaimed;
};

#endif
