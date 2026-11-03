// SPDX-License-Identifier: GPL-2.0
/*
 * Events that explain what numasnap decides from procfs:
 *   kswapd_stat  when each node's kswapd last woke up and went to sleep
 *   refault      refaults per cgroup of the faulting task (who is thrashing)
 *   kills        recent SIGKILLs: who killed whom
 *
 * No vmlinux.h / CO-RE: the target kernel (5.4 elrepo) ships no BTF, so
 * tracepoint records are laid out by hand from
 * /sys/kernel/debug/tracing/events/<sys>/<event>/format.
 */
#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>

#include "numasnap.h"

struct kswapd_args {		/* vmscan/mm_vmscan_kswapd_{wake,sleep} */
	__u64 common;
	int nid;
};

struct signal_args {		/* signal/signal_generate */
	__u64 common;
	int sig;
	int errno_;
	int code;
	char comm[16];
	int pid;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, NS_MAX_NODES);
	__type(key, __u32);
	__type(value, struct ns_kswapd);
} kswapd_stat SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, __u64);
} refault SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, NS_KILL_RING);
	__type(key, __u32);
	__type(value, struct ns_kill);
} kills SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} kill_seq SEC(".maps");

SEC("tracepoint/vmscan/mm_vmscan_kswapd_wake")
int on_kswapd_wake(struct kswapd_args *ctx)
{
	__u32 nid = ctx->nid;
	struct ns_kswapd *k = bpf_map_lookup_elem(&kswapd_stat, &nid);

	if (k) {
		__sync_fetch_and_add(&k->wake_cnt, 1);
		k->last_wake_ns = bpf_ktime_get_ns();
	}
	return 0;
}

SEC("tracepoint/vmscan/mm_vmscan_kswapd_sleep")
int on_kswapd_sleep(struct kswapd_args *ctx)
{
	__u32 nid = ctx->nid;
	struct ns_kswapd *k = bpf_map_lookup_elem(&kswapd_stat, &nid);

	if (k) {
		__sync_fetch_and_add(&k->sleep_cnt, 1);
		k->last_sleep_ns = bpf_ktime_get_ns();
	}
	return 0;
}

/* void workingset_refault(struct page *page, void *shadow) */
SEC("kprobe/workingset_refault")
int on_refault(struct pt_regs *ctx)
{
	/* 5.4 cgroup id is generation << 32 | inode; userspace knows the inode */
	__u64 cgid = bpf_get_current_cgroup_id() & 0xffffffff, one = 1, *v;

	v = bpf_map_lookup_elem(&refault, &cgid);
	if (v)
		__sync_fetch_and_add(v, 1);
	else
		bpf_map_update_elem(&refault, &cgid, &one, BPF_NOEXIST);
	return 0;
}

SEC("tracepoint/signal/signal_generate")
int on_signal(struct signal_args *ctx)
{
	__u32 zero = 0, slot;
	__u64 *seq;
	struct ns_kill *k;

	if (ctx->sig != 9)	/* SIGKILL */
		return 0;
	seq = bpf_map_lookup_elem(&kill_seq, &zero);
	if (!seq)
		return 0;
	/* 5.4 has no atomic fetch-and-add (BPF_FETCH is 5.12); a rare lost slot is fine */
	slot = *seq % NS_KILL_RING;
	__sync_fetch_and_add(seq, 1);
	k = bpf_map_lookup_elem(&kills, &slot);
	if (!k)
		return 0;
	k->ts_ns = bpf_ktime_get_ns();
	k->sender_pid = bpf_get_current_pid_tgid() >> 32;
	k->target_pid = ctx->pid;
	bpf_get_current_comm(k->sender_comm, sizeof(k->sender_comm));
	bpf_probe_read(k->target_comm, sizeof(k->target_comm), ctx->comm);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
