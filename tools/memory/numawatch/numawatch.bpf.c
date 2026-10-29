// SPDX-License-Identifier: GPL-2.0
/*
 * numawatch: per-NUMA-node reclaim activity.
 *
 * Hooks (all vmscan tracepoints):
 *   mm_vmscan_wakeup_kswapd            allocation pressure per node
 *   mm_vmscan_kswapd_wake / _sleep     kswapd busy time per node
 *   mm_vmscan_direct_reclaim_begin/end direct reclaim, attributed to the CPU's node
 *   mm_vmscan_node_reclaim_begin/end   zone_reclaim_mode stalls (optional)
 *   mm_vmscan_lru_shrink_inactive      scanned vs reclaimed per node
 */
#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "tp_vmscan.h"
#include "numawatch.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, NUMA_MAX_NODES);
	__type(key, __u32);
	__type(value, struct node_stat);
} stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, NUMA_MAX_NODES);
	__type(key, __u32);
	__type(value, __u64);
} kswapd_start SEC(".maps");

struct reclaim_start {
	__u64 ts;
	__u32 nid;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u32);
	__type(value, struct reclaim_start);
} direct_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u32);
	__type(value, struct reclaim_start);
} nrcl_start SEC(".maps");

static __always_inline struct node_stat *get_stat(__u32 nid)
{
	if (nid >= NUMA_MAX_NODES)
		return NULL;
	return bpf_map_lookup_elem(&stats, &nid);
}

SEC("tp/vmscan/mm_vmscan_wakeup_kswapd")
int handle_wakeup_kswapd(struct tp_wakeup_kswapd *ctx)
{
	struct node_stat *s = get_stat(ctx->nid);

	if (s)
		s->wakeup_kswapd++;
	return 0;
}

SEC("tp/vmscan/mm_vmscan_kswapd_wake")
int handle_kswapd_wake(struct tp_kswapd_wake *ctx)
{
	__u32 nid = ctx->nid;
	__u64 ts = bpf_ktime_get_ns();

	if (nid < NUMA_MAX_NODES)
		bpf_map_update_elem(&kswapd_start, &nid, &ts, BPF_ANY);
	return 0;
}

SEC("tp/vmscan/mm_vmscan_kswapd_sleep")
int handle_kswapd_sleep(struct tp_kswapd_sleep *ctx)
{
	__u32 nid = ctx->nid;
	struct node_stat *s;
	__u64 *tsp;

	tsp = bpf_map_lookup_elem(&kswapd_start, &nid);
	if (!tsp || !*tsp)
		return 0;
	s = get_stat(nid);
	if (s) {
		s->kswapd_runs++;
		s->kswapd_ns += bpf_ktime_get_ns() - *tsp;
	}
	*tsp = 0;
	return 0;
}

static __always_inline void record_begin(void *map, __u32 nid)
{
	__u32 pid = (__u32)bpf_get_current_pid_tgid();
	struct reclaim_start rs = { .ts = bpf_ktime_get_ns(), .nid = nid };

	bpf_map_update_elem(map, &pid, &rs, BPF_ANY);
}

SEC("tp/vmscan/mm_vmscan_direct_reclaim_begin")
int handle_direct_begin(void *ctx)
{
	record_begin(&direct_start, bpf_get_numa_node_id());
	return 0;
}

SEC("tp/vmscan/mm_vmscan_direct_reclaim_end")
int handle_direct_end(void *ctx)
{
	__u32 pid = (__u32)bpf_get_current_pid_tgid();
	struct reclaim_start *rs;
	struct node_stat *s;
	__u64 delta;

	rs = bpf_map_lookup_elem(&direct_start, &pid);
	if (!rs)
		return 0;
	delta = bpf_ktime_get_ns() - rs->ts;
	s = get_stat(rs->nid);
	if (s) {
		s->direct_cnt++;
		s->direct_ns += delta;
		if (delta > s->direct_max_ns)
			s->direct_max_ns = delta;
	}
	bpf_map_delete_elem(&direct_start, &pid);
	return 0;
}

SEC("tp/vmscan/mm_vmscan_node_reclaim_begin")
int handle_nrcl_begin(struct tp_node_reclaim_begin *ctx)
{
	record_begin(&nrcl_start, ctx->nid);
	return 0;
}

SEC("tp/vmscan/mm_vmscan_node_reclaim_end")
int handle_nrcl_end(void *ctx)
{
	__u32 pid = (__u32)bpf_get_current_pid_tgid();
	struct reclaim_start *rs;
	struct node_stat *s;
	__u64 delta;

	rs = bpf_map_lookup_elem(&nrcl_start, &pid);
	if (!rs)
		return 0;
	delta = bpf_ktime_get_ns() - rs->ts;
	s = get_stat(rs->nid);
	if (s) {
		s->nrcl_cnt++;
		s->nrcl_ns += delta;
		if (delta > s->nrcl_max_ns)
			s->nrcl_max_ns = delta;
	}
	bpf_map_delete_elem(&nrcl_start, &pid);
	return 0;
}

/* kswapd threads are named "kswapd<nid>" */
static __always_inline int is_kswapd(void)
{
	char comm[8];

	bpf_get_current_comm(comm, sizeof(comm));
	return comm[0] == 'k' && comm[1] == 's' && comm[2] == 'w' &&
	       comm[3] == 'a' && comm[4] == 'p' && comm[5] == 'd';
}

SEC("tp/vmscan/mm_vmscan_lru_shrink_inactive")
int handle_shrink_inactive(struct tp_lru_shrink_inactive *ctx)
{
	struct node_stat *s = get_stat(ctx->nid);

	if (s) {
		s->scanned += ctx->nr_scanned;
		s->reclaimed += ctx->nr_reclaimed;
		if (is_kswapd())
			s->kswapd_scanned += ctx->nr_scanned;
	}
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
