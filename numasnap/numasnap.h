/* SPDX-License-Identifier: GPL-2.0 */
#ifndef NUMASNAP_H
#define NUMASNAP_H

#define NS_MAX_NODES	8
#define NS_KILL_RING	64

struct ns_kswapd {		/* map kswapd_stat, ARRAY, key = nid */
	__u64 wake_cnt;
	__u64 sleep_cnt;
	__u64 last_wake_ns;
	__u64 last_sleep_ns;
};

struct ns_kill {		/* map kills, ARRAY ring, key = seq % NS_KILL_RING */
	__u64 ts_ns;
	__u32 sender_pid;
	__u32 target_pid;
	char sender_comm[16];
	char target_comm[16];
};

#endif
