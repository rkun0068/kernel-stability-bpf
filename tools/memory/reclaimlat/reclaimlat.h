/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __RECLAIMLAT_H
#define __RECLAIMLAT_H

#define TASK_COMM_LEN 16
#define RECLAIM_MAX_SLOTS 27

struct event {
	__u64 delta_ns;
	__u64 nr_reclaimed;
	__u32 pid;
	__u32 tgid;
	__u32 gfp_flags;
	__s32 order;
	char comm[TASK_COMM_LEN];
};

#endif
