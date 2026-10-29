/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Context layouts of the vmscan tracepoints, copied from
 * /sys/kernel/debug/tracing/events/vmscan/<name>/format.
 *
 * Used instead of vmlinux.h so the tools build and load on kernels without
 * BTF (e.g. elrepo kernel-lt 5.4). These layouts are not relocated at load
 * time: if a target kernel's format file differs, update this header.
 * Verified on 5.4.139-1.el7.elrepo.x86_64.
 */
#ifndef __KSB_TP_VMSCAN_H
#define __KSB_TP_VMSCAN_H

#include <linux/types.h>

/* common_type, common_flags, common_preempt_count, common_pid */
struct tp_common {
	__u16 type;
	__u8 flags;
	__u8 preempt_count;
	__s32 pid;
};

struct tp_direct_reclaim_begin {
	struct tp_common common;
	__s32 order;
	__u32 gfp_flags;
};

/* shared by mm_vmscan_direct_reclaim_end and mm_vmscan_node_reclaim_end */
struct tp_reclaim_end {
	struct tp_common common;
	__u64 nr_reclaimed;
};

struct tp_node_reclaim_begin {
	struct tp_common common;
	__s32 nid;
	__s32 order;
	__u32 gfp_flags;
};

struct tp_wakeup_kswapd {
	struct tp_common common;
	__s32 nid;
	__s32 zid;
	__s32 order;
	__u32 gfp_flags;
};

struct tp_kswapd_wake {
	struct tp_common common;
	__s32 nid;
	__s32 zid;
	__s32 order;
};

struct tp_kswapd_sleep {
	struct tp_common common;
	__s32 nid;
};

struct tp_lru_shrink_inactive {
	struct tp_common common;
	__s32 nid;
	__u32 __pad;
	__u64 nr_scanned;
	__u64 nr_reclaimed;
};

#endif
