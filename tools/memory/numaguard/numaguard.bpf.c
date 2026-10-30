// SPDX-License-Identifier: GPL-2.0
/* Pages allocated per (cgroup, NUMA node). numaguard loads this only around an incident. */
#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "numaguard.h"

/* kmem:mm_page_alloc on 5.4: 8-byte common header, then pfn and order */
struct page_alloc {
	__u64 common;
	__u64 pfn;
	__u32 order;
};

/* exclusive end pfn of each node, ascending; set by numaguard */
const volatile __u64 node_end_pfn[MAX_NODES];

/* key: cgroup id << 8 | node, value: pages */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);
	__type(value, __u64);
} allocs SEC(".maps");

SEC("tp/kmem/mm_page_alloc")
int handle_alloc(struct page_alloc *ctx)
{
	__u64 nid = MAX_NODES, key, pages = 1ULL << (ctx->order & 15), *cnt;

#pragma unroll
	for (int i = MAX_NODES - 1; i >= 0; i--)
		if (ctx->pfn < node_end_pfn[i])
			nid = i;
	if (nid == MAX_NODES)
		return 0;

	key = bpf_get_current_cgroup_id() << 8 | nid;
	cnt = bpf_map_lookup_elem(&allocs, &key);
	if (cnt)
		__sync_fetch_and_add(cnt, pages);
	else
		bpf_map_update_elem(&allocs, &key, &pages, BPF_NOEXIST);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
