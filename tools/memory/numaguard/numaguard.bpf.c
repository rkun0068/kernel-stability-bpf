// SPDX-License-Identifier: GPL-2.0
/*
 * Pages allocated per (cgroup, NUMA node), from kmem:mm_page_alloc.
 *
 * Page allocation is a hot path, so numaguard attaches this only while a node
 * is heading for a hang, and uses it to name the containers that are filling
 * the thrashing node.
 */
#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "numaguard.h"

/* from /sys/kernel/debug/tracing/events/kmem/mm_page_alloc/format (5.4) */
struct tp_mm_page_alloc {
	__u64 common;
	__u64 pfn;
	__u32 order;
	__u32 gfp_flags;
};

/* exclusive end pfn of each node, in ascending order; set by numaguard */
const volatile __u64 node_end_pfn[MAX_NODES];

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 8192);
	__type(key, struct alloc_key);
	__type(value, __u64);
} allocs SEC(".maps");

SEC("tp/kmem/mm_page_alloc")
int handle_alloc(struct tp_mm_page_alloc *ctx)
{
	struct alloc_key key = { .cgid = bpf_get_current_cgroup_id(), .nid = MAX_NODES, .pad = 0 };
	__u64 pages = 1ULL << (ctx->order & 15), *cnt;

#pragma unroll
	for (int i = MAX_NODES - 1; i >= 0; i--)
		if (ctx->pfn < node_end_pfn[i])
			key.nid = i;
	if (key.nid == MAX_NODES)
		return 0;

	cnt = bpf_map_lookup_elem(&allocs, &key);
	if (cnt)
		*cnt += pages;
	else
		bpf_map_update_elem(&allocs, &key, &pages, BPF_NOEXIST);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
