// SPDX-License-Identifier: GPL-2.0
/*
 * reclaimlat: trace Direct Reclaim latency per task.
 *
 * Hooks: tracepoint vmscan:mm_vmscan_direct_reclaim_begin / _end
 * (stable since 2.6.x; ctx layouts in include/tp_vmscan.h).
 */
#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "tp_vmscan.h"
#include "reclaimlat.h"

const volatile __u32 targ_tgid = 0;
const volatile __u64 min_ns = 0;

struct start_info {
	__u64 ts;
	__u32 gfp_flags;
	__s32 order;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u32);
	__type(value, struct start_info);
} start SEC(".maps");

/* perf buffer rather than ringbuf: ringbuf needs kernel >= 5.8 */
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, RECLAIM_MAX_SLOTS);
	__type(key, __u32);
	__type(value, __u32);
} hist SEC(".maps");

static __always_inline __u32 log2l(__u64 v)
{
	__u32 r = 0;

	while (v > 1 && r < 63) {
		v >>= 1;
		r++;
	}
	return r;
}

SEC("tp/vmscan/mm_vmscan_direct_reclaim_begin")
int handle_begin(struct tp_direct_reclaim_begin *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u32 pid = (__u32)id, tgid = id >> 32;
	struct start_info si = {};

	if (targ_tgid && targ_tgid != tgid)
		return 0;

	si.ts = bpf_ktime_get_ns();
	si.order = ctx->order;
	si.gfp_flags = ctx->gfp_flags;
	bpf_map_update_elem(&start, &pid, &si, BPF_ANY);
	return 0;
}

SEC("tp/vmscan/mm_vmscan_direct_reclaim_end")
int handle_end(struct tp_reclaim_end *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u32 pid = (__u32)id;
	struct start_info *si;
	struct event e = {};
	__u64 delta;
	__u32 slot, *cnt;

	si = bpf_map_lookup_elem(&start, &pid);
	if (!si)
		return 0;

	delta = bpf_ktime_get_ns() - si->ts;

	slot = log2l(delta / 1000);
	if (slot >= RECLAIM_MAX_SLOTS)
		slot = RECLAIM_MAX_SLOTS - 1;
	cnt = bpf_map_lookup_elem(&hist, &slot);
	if (cnt)
		__sync_fetch_and_add(cnt, 1);

	if (delta < min_ns)
		goto out;

	e.delta_ns = delta;
	e.nr_reclaimed = ctx->nr_reclaimed;
	e.pid = pid;
	e.tgid = id >> 32;
	e.order = si->order;
	e.gfp_flags = si->gfp_flags;
	bpf_get_current_comm(e.comm, sizeof(e.comm));
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
out:
	bpf_map_delete_elem(&start, &pid);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
