// SPDX-License-Identifier: GPL-2.0
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "common.h"
#include "numawatch.h"
#include "numawatch.skel.h"

static struct env {
	int interval;
	int duration;
	bool json;
	bool verbose;
} env = { .interval = 10 };

static volatile sig_atomic_t exiting;

const char *argp_program_version = "numawatch 0.1.0";
static const char doc[] =
	"Per-NUMA-node memory distribution and reclaim activity.\n\n"
	"EXAMPLES:\n"
	"  numawatch               # table every 10s\n"
	"  numawatch -i 30 -j      # JSON Lines every 30s, for long-running capture\n"
	"  numawatch -i 5 -d 60\n";

static const struct argp_option opts[] = {
	{ "interval", 'i', "SEC", 0, "Report interval in seconds (default 10)" },
	{ "duration", 'd', "SEC", 0, "Run for SEC seconds then exit" },
	{ "json", 'j', NULL, 0, "Emit one JSON object per node per interval" },
	{ "verbose", 'v', NULL, 0, "Verbose libbpf output" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'i': env.interval = strtol(arg, NULL, 10); break;
	case 'd': env.duration = strtol(arg, NULL, 10); break;
	case 'j': env.json = true; break;
	case 'v': env.verbose = true; break;
	default: return ARGP_ERR_UNKNOWN;
	}
	if (env.interval <= 0)
		argp_error(state, "interval must be positive");
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

/* Counters read from procfs/sysfs; numastat values are cumulative. */
struct node_proc {
	bool online;
	__u64 total_kb, free_kb, file_kb, anon_kb;
	__u64 wm_min, wm_low, wm_high;	/* pages, summed over the node's zones */
	__u64 numa_hit, numa_miss, numa_foreign;
};

static struct node_proc cur[NUMA_MAX_NODES], prev[NUMA_MAX_NODES];
static long page_kb;

static void read_node_meminfo(int nid, struct node_proc *np)
{
	char path[128], line[256], key[64];
	unsigned long long val;
	FILE *f;

	snprintf(path, sizeof(path), "/sys/devices/system/node/node%d/meminfo", nid);
	f = fopen(path, "r");
	if (!f)
		return;
	np->online = true;
	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "Node %*d %63[^:]: %llu", key, &val) != 2)
			continue;
		if (!strcmp(key, "MemTotal"))
			np->total_kb = val;
		else if (!strcmp(key, "MemFree"))
			np->free_kb = val;
		else if (!strcmp(key, "FilePages"))
			np->file_kb = val;
		else if (!strcmp(key, "AnonPages"))
			np->anon_kb = val;
	}
	fclose(f);

	snprintf(path, sizeof(path), "/sys/devices/system/node/node%d/numastat", nid);
	f = fopen(path, "r");
	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "%63s %llu", key, &val) != 2)
			continue;
		if (!strcmp(key, "numa_hit"))
			np->numa_hit = val;
		else if (!strcmp(key, "numa_miss"))
			np->numa_miss = val;
		else if (!strcmp(key, "numa_foreign"))
			np->numa_foreign = val;
	}
	fclose(f);
}

static void read_zoneinfo(void)
{
	char line[256];
	unsigned long long val;
	int nid = -1;
	FILE *f = fopen("/proc/zoneinfo", "r");

	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "Node %d, zone", &nid) == 1)
			continue;
		if (nid < 0 || nid >= NUMA_MAX_NODES)
			continue;
		if (sscanf(line, " min %llu", &val) == 1)
			cur[nid].wm_min += val;
		else if (sscanf(line, " low %llu", &val) == 1)
			cur[nid].wm_low += val;
		else if (sscanf(line, " high %llu", &val) == 1)
			cur[nid].wm_high += val;
	}
	fclose(f);
}

static void read_proc(void)
{
	int nid;

	memcpy(prev, cur, sizeof(cur));
	memset(cur, 0, sizeof(cur));
	for (nid = 0; nid < NUMA_MAX_NODES; nid++)
		read_node_meminfo(nid, &cur[nid]);
	read_zoneinfo();
}

static int read_zone_reclaim_mode(void)
{
	int mode = -1;
	FILE *f = fopen("/proc/sys/vm/zone_reclaim_mode", "r");

	if (f) {
		if (fscanf(f, "%d", &mode) != 1)
			mode = -1;
		fclose(f);
	}
	return mode;
}

/* Sum the per-CPU slots for every node, then zero the map for the next interval. */
static int collect_bpf(int fd, int ncpus, struct node_stat *out)
{
	struct node_stat *vals = calloc(ncpus, sizeof(*vals));
	__u32 nid;
	int c;

	if (!vals)
		return -ENOMEM;
	for (nid = 0; nid < NUMA_MAX_NODES; nid++) {
		struct node_stat *o = &out[nid];

		memset(o, 0, sizeof(*o));
		if (!cur[nid].online)
			continue;
		if (bpf_map_lookup_elem(fd, &nid, vals))
			continue;
		for (c = 0; c < ncpus; c++) {
			struct node_stat *v = &vals[c];

			o->wakeup_kswapd += v->wakeup_kswapd;
			o->kswapd_runs += v->kswapd_runs;
			o->kswapd_ns += v->kswapd_ns;
			o->direct_cnt += v->direct_cnt;
			o->direct_ns += v->direct_ns;
			o->nrcl_cnt += v->nrcl_cnt;
			o->nrcl_ns += v->nrcl_ns;
			o->scanned += v->scanned;
			o->reclaimed += v->reclaimed;
			if (v->direct_max_ns > o->direct_max_ns)
				o->direct_max_ns = v->direct_max_ns;
			if (v->nrcl_max_ns > o->nrcl_max_ns)
				o->nrcl_max_ns = v->nrcl_max_ns;
		}
		memset(vals, 0, ncpus * sizeof(*vals));
		bpf_map_update_elem(fd, &nid, vals, BPF_ANY);
	}
	free(vals);
	return 0;
}

/* Anomaly flags, comma-separated into buf. */
static void node_flags(int nid, const struct node_stat *s, char *buf, int len)
{
	const struct node_proc *n = &cur[nid], *p = &prev[nid];
	__u64 free_pg = n->free_kb / page_kb;
	__u64 dhit = n->numa_hit - p->numa_hit, dmiss = n->numa_miss - p->numa_miss;
	bool pressure = free_pg <= n->wm_high;
	int other, off = 0;

	buf[0] = '\0';
#define ADD(f) (off += snprintf(buf + off, len - off, "%s%s", off ? "," : "", f))
	if (free_pg <= n->wm_min)
		ADD("BELOW_MIN");
	else if (free_pg <= n->wm_low)
		ADD("BELOW_LOW");
	/* this node is under pressure while another still has >20% free */
	if (pressure) {
		for (other = 0; other < NUMA_MAX_NODES; other++) {
			if (other == nid || !cur[other].online || !cur[other].total_kb)
				continue;
			if (cur[other].free_kb * 5 > cur[other].total_kb) {
				ADD("IMBALANCE");
				break;
			}
		}
	}
	if (s->nrcl_cnt)
		ADD("NODE_RECLAIM");
	if (dhit + dmiss > 1000 && dmiss * 10 > dhit + dmiss)
		ADD("HIGH_MISS");
	if (s->scanned > 1000 && s->reclaimed * 10 < s->scanned)
		ADD("LOW_EFFICIENCY");
	if (!off)
		ADD("-");
#undef ADD
}

static void report(const struct node_stat *st)
{
	char ts[16], flags[128];
	time_t now = time(NULL);
	int nid;

	fmt_now(ts, sizeof(ts));
	if (!env.json)
		printf("\n%-8s %-4s %9s %9s %9s %8s %7s %7s %9s %6s %9s %6s %9s %5s  %s\n",
		       ts, "NODE", "FREE(MB)", "LOW(MB)", "FILE(MB)", "MISS/s", "KSWAKE",
		       "KSW(ms)", "DIRECT", "D_MAX", "NODE_RCL", "N_MAX", "SCANNED", "EFF%",
		       "FLAGS");

	for (nid = 0; nid < NUMA_MAX_NODES; nid++) {
		const struct node_proc *n = &cur[nid], *p = &prev[nid];
		const struct node_stat *s = &st[nid];
		double miss_s = (double)(n->numa_miss - p->numa_miss) / env.interval;
		unsigned eff = s->scanned ? (unsigned)(s->reclaimed * 100 / s->scanned) : 100;

		if (!n->online)
			continue;
		node_flags(nid, s, flags, sizeof(flags));

		if (env.json) {
			printf("{\"ts\":%ld,\"interval\":%d,\"node\":%d,"
			       "\"total_kb\":%llu,\"free_kb\":%llu,\"file_kb\":%llu,\"anon_kb\":%llu,"
			       "\"wm_min_kb\":%llu,\"wm_low_kb\":%llu,\"wm_high_kb\":%llu,"
			       "\"numa_miss_per_s\":%.1f,\"wakeup_kswapd\":%llu,"
			       "\"kswapd_runs\":%llu,\"kswapd_ms\":%.3f,"
			       "\"direct_cnt\":%llu,\"direct_ms\":%.3f,\"direct_max_ms\":%.3f,"
			       "\"node_reclaim_cnt\":%llu,\"node_reclaim_ms\":%.3f,"
			       "\"node_reclaim_max_ms\":%.3f,"
			       "\"scanned\":%llu,\"reclaimed\":%llu,\"flags\":\"%s\"}\n",
			       (long)now, env.interval, nid,
			       (unsigned long long)n->total_kb, (unsigned long long)n->free_kb,
			       (unsigned long long)n->file_kb, (unsigned long long)n->anon_kb,
			       (unsigned long long)(n->wm_min * page_kb),
			       (unsigned long long)(n->wm_low * page_kb),
			       (unsigned long long)(n->wm_high * page_kb), miss_s,
			       (unsigned long long)s->wakeup_kswapd,
			       (unsigned long long)s->kswapd_runs, s->kswapd_ns / 1e6,
			       (unsigned long long)s->direct_cnt, s->direct_ns / 1e6,
			       s->direct_max_ns / 1e6, (unsigned long long)s->nrcl_cnt,
			       s->nrcl_ns / 1e6, s->nrcl_max_ns / 1e6,
			       (unsigned long long)s->scanned, (unsigned long long)s->reclaimed,
			       flags);
		} else {
			printf("%-8s %-4d %9llu %9llu %9llu %8.1f %7llu %7.0f %9llu %6.1f %9llu %6.1f %9llu %5u  %s\n",
			       "", nid, (unsigned long long)(n->free_kb >> 10),
			       (unsigned long long)(n->wm_low * page_kb >> 10),
			       (unsigned long long)(n->file_kb >> 10), miss_s,
			       (unsigned long long)s->wakeup_kswapd, s->kswapd_ns / 1e6,
			       (unsigned long long)s->direct_cnt, s->direct_max_ns / 1e6,
			       (unsigned long long)s->nrcl_cnt, s->nrcl_max_ns / 1e6,
			       (unsigned long long)s->scanned, eff, flags);
		}
	}
	fflush(stdout);
}

static bool tp_exists(const char *cat, const char *name)
{
	char path[256];

	snprintf(path, sizeof(path), "/sys/kernel/tracing/events/%s/%s", cat, name);
	if (!access(path, F_OK))
		return true;
	snprintf(path, sizeof(path), "/sys/kernel/debug/tracing/events/%s/%s", cat, name);
	return !access(path, F_OK);
}

int main(int argc, char **argv)
{
	static const struct argp argp = { .options = opts, .parser = parse_arg, .doc = doc };
	static struct node_stat st[NUMA_MAX_NODES];
	struct numawatch_bpf *skel;
	int ncpus, err, mode, elapsed = 0;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);
	bump_memlock_rlimit();
	page_kb = sysconf(_SC_PAGESIZE) / 1024;
	ncpus = libbpf_num_possible_cpus();
	if (ncpus < 0) {
		fprintf(stderr, "failed to get possible cpus: %d\n", ncpus);
		return 1;
	}

	skel = numawatch_bpf__open();
	if (!skel) {
		fprintf(stderr, "failed to open BPF skeleton\n");
		return 1;
	}
	/* node_reclaim tracepoints only exist on CONFIG_NUMA kernels */
	if (!tp_exists("vmscan", "mm_vmscan_node_reclaim_begin")) {
		bpf_program__set_autoload(skel->progs.handle_nrcl_begin, false);
		bpf_program__set_autoload(skel->progs.handle_nrcl_end, false);
	}

	err = numawatch_bpf__load(skel);
	if (err) {
		fprintf(stderr, "failed to load BPF skeleton: %d\n", err);
		goto cleanup;
	}
	err = numawatch_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	mode = read_zone_reclaim_mode();
	if (!env.json)
		printf("Tracing NUMA reclaim every %ds, zone_reclaim_mode=%d. Hit Ctrl-C to end.\n",
		       env.interval, mode);

	read_proc();
	while (!exiting) {
		sleep(env.interval);
		elapsed += env.interval;
		read_proc();
		err = collect_bpf(bpf_map__fd(skel->maps.stats), ncpus, st);
		if (err)
			break;
		report(st);
		if (env.duration && elapsed >= env.duration)
			break;
	}

cleanup:
	numawatch_bpf__destroy(skel);
	return err < 0 ? -err : err;
}
