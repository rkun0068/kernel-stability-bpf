// SPDX-License-Identifier: GPL-2.0
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "common.h"
#include "reclaimlat.h"
#include "reclaimlat.skel.h"

#if defined(__has_include)
#if __has_include(<bpf/libbpf_version.h>)
#include <bpf/libbpf_version.h>
#endif
#endif

static struct env {
	pid_t pid;
	__u64 min_us;
	int duration;
	bool hist_only;
	bool verbose;
} env;

static volatile sig_atomic_t exiting;

const char *argp_program_version = "reclaimlat 0.1.0";
static const char doc[] =
	"Trace Direct Reclaim latency.\n\n"
	"EXAMPLES:\n"
	"  reclaimlat              # trace all direct reclaims\n"
	"  reclaimlat -m 10000     # only print reclaims >= 10ms\n"
	"  reclaimlat -p 1234 -d 60\n"
	"  reclaimlat -H -d 30     # histogram only\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Trace this process (tgid) only" },
	{ "min", 'm', "USEC", 0, "Only print events slower than USEC" },
	{ "duration", 'd', "SEC", 0, "Run for SEC seconds then exit" },
	{ "hist", 'H', NULL, 0, "Histogram only, no per-event output" },
	{ "verbose", 'v', NULL, 0, "Verbose libbpf output" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'p': env.pid = strtol(arg, NULL, 10); break;
	case 'm': env.min_us = strtoull(arg, NULL, 10); break;
	case 'd': env.duration = strtol(arg, NULL, 10); break;
	case 'H': env.hist_only = true; break;
	case 'v': env.verbose = true; break;
	default: return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *fmt, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, fmt, args);
}

static void sig_handler(int sig)
{
	exiting = 1;
}

static void handle_event(void *ctx, int cpu, void *data, __u32 size)
{
	const struct event *e = data;
	char ts[16];

	fmt_now(ts, sizeof(ts));
	printf("%-8s %-7u %-7u %-16s %-5d 0x%-8x %-12llu %10.3f\n", ts, e->tgid, e->pid,
	       e->comm, e->order, e->gfp_flags, (unsigned long long)e->nr_reclaimed,
	       e->delta_ns / 1e6);
}

static void handle_lost(void *ctx, int cpu, __u64 cnt)
{
	fprintf(stderr, "lost %llu events on CPU %d\n", (unsigned long long)cnt, cpu);
}

/* perf_buffer__new() changed signature in libbpf 1.0; support 0.x too */
static struct perf_buffer *open_perf_buffer(int map_fd)
{
#if defined(LIBBPF_MAJOR_VERSION) && LIBBPF_MAJOR_VERSION >= 1
	return perf_buffer__new(map_fd, 64, handle_event, handle_lost, NULL, NULL);
#else
	struct perf_buffer_opts opts = {
		.sample_cb = handle_event,
		.lost_cb = handle_lost,
	};

	return perf_buffer__new(map_fd, 64, &opts);
#endif
}

static void print_hist(struct reclaimlat_bpf *skel)
{
	__u32 vals[RECLAIM_MAX_SLOTS] = {};
	__u32 i;
	int fd = bpf_map__fd(skel->maps.hist);

	for (i = 0; i < RECLAIM_MAX_SLOTS; i++)
		bpf_map_lookup_elem(fd, &i, &vals[i]);
	printf("\nDirect reclaim latency histogram:\n");
	print_log2_hist(vals, RECLAIM_MAX_SLOTS, "usecs");
}

int main(int argc, char **argv)
{
	static const struct argp argp = { .options = opts, .parser = parse_arg, .doc = doc };
	struct perf_buffer *pb = NULL;
	struct reclaimlat_bpf *skel;
	time_t end;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);
	bump_memlock_rlimit();

	skel = reclaimlat_bpf__open();
	if (!skel) {
		fprintf(stderr, "failed to open BPF skeleton\n");
		return 1;
	}
	skel->rodata->targ_tgid = env.pid;
	/* in hist-only mode never emit events */
	skel->rodata->min_ns = env.hist_only ? ~0ULL : env.min_us * 1000;

	err = reclaimlat_bpf__load(skel);
	if (err) {
		fprintf(stderr, "failed to load BPF skeleton: %d\n", err);
		goto cleanup;
	}
	err = reclaimlat_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	pb = open_perf_buffer(bpf_map__fd(skel->maps.events));
	err = libbpf_get_error(pb);
	if (err) {
		pb = NULL;
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	printf("Tracing direct reclaim... Hit Ctrl-C to end.\n");
	if (!env.hist_only)
		printf("%-8s %-7s %-7s %-16s %-5s %-10s %-12s %10s\n", "TIME", "TGID", "PID",
		       "COMM", "ORDER", "GFP", "NR_RECLAIMED", "LAT(ms)");

	end = env.duration ? time(NULL) + env.duration : 0;
	while (!exiting) {
		err = perf_buffer__poll(pb, 100);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "perf buffer poll error: %d\n", err);
			break;
		}
		err = 0;
		if (end && time(NULL) >= end)
			break;
	}

	print_hist(skel);

cleanup:
	perf_buffer__free(pb);
	reclaimlat_bpf__destroy(skel);
	return err < 0 ? -err : err;
}
