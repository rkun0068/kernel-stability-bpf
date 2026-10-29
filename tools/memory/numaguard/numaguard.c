// SPDX-License-Identifier: GPL-2.0
/*
 * numaguard: detect the NUMA-node thrashing that precedes a host hang and
 * publish a verdict for the NodeManager in /run/numaguard/state.
 *
 *   warn: a node's kswapd has stopped scanning while the node's free memory
 *         stays below its high watermark, for 10 minutes.
 *   kill: the host is stalled on IO (IO PSI full and iowait) and a node has
 *         no page cache left, free memory near its high watermark, heavy
 *         scanning and almost nothing reclaimed, for 60 seconds.
 *
 * Without --enforce (dry run) a kill verdict is only logged; the state file
 * says warn.
 */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "../numawatch/numawatch.h"
#include "numaguard.skel.h"

/* Thresholds, from 5 hangs on 4 hosts. See README.md. */
#define WARN_SECS	600
#define KILL_SECS	60
#define KILL_HOLD_SECS	300		/* keep a kill verdict at least this long */
#define IO_FULL_MIN	80.0		/* /proc/pressure/io full avg10 */
#define IOWAIT_MIN	80.0		/* % of CPU time */
#define FILE_MAX_KB	(1ULL << 20)	/* page cache below 1G */
#define FREE_MARGIN_KB	(1ULL << 20)	/* free below high watermark + 1G */
#define SCAN_MIN	600000		/* pages scanned per second */
#define EFF_MAX		10		/* % of scanned pages reclaimed */
#define KSWAPD_IDLE	100		/* kswapd pages scanned per second */

#define RUN_DIR		"/run/numaguard"
#define STATE_FILE	RUN_DIR "/state"
#define EVENT_LOG	RUN_DIR "/events.log"

enum verdict { OK, WARN, KILL };
static const char *verdict_name[] = { "ok", "warn", "kill" };

struct node {
	bool online;
	__u64 free_kb, file_kb, high_kb;
	__u64 scanned, reclaimed, kswapd_scanned;	/* pages, last second */
	int warn_secs, kill_secs;			/* how long each rule held */
};

static struct node nodes[NUMA_MAX_NODES];
static long page_kb;

static void read_nodes(void)
{
	char path[64], line[256], key[32];
	unsigned long long val;
	int nid = -1;
	FILE *f;

	for (int i = 0; i < NUMA_MAX_NODES; i++) {
		struct node *n = &nodes[i];

		snprintf(path, sizeof(path), "/sys/devices/system/node/node%d/meminfo", i);
		f = fopen(path, "r");
		n->online = f != NULL;
		n->high_kb = 0;
		if (!f)
			continue;
		while (fgets(line, sizeof(line), f)) {
			if (sscanf(line, "Node %*d %31[^:]: %llu", key, &val) != 2)
				continue;
			if (!strcmp(key, "MemFree"))
				n->free_kb = val;
			else if (!strcmp(key, "FilePages"))
				n->file_kb = val;
		}
		fclose(f);
	}

	/* a node's high watermark is the sum over its zones */
	f = fopen("/proc/zoneinfo", "r");
	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "Node %d, zone", &nid) == 1)
			continue;
		if (nid >= 0 && nid < NUMA_MAX_NODES && sscanf(line, " high %llu", &val) == 1)
			nodes[nid].high_kb += val * page_kb;
	}
	fclose(f);
}

/* Per-node scan counters from BPF, summed over CPUs and then reset. */
static void read_bpf(int map_fd, struct node_stat *percpu, int ncpus)
{
	for (__u32 nid = 0; nid < NUMA_MAX_NODES; nid++) {
		struct node *n = &nodes[nid];

		n->scanned = n->reclaimed = n->kswapd_scanned = 0;
		if (!n->online || bpf_map_lookup_elem(map_fd, &nid, percpu))
			continue;
		for (int c = 0; c < ncpus; c++) {
			n->scanned += percpu[c].scanned;
			n->reclaimed += percpu[c].reclaimed;
			n->kswapd_scanned += percpu[c].kswapd_scanned;
		}
		memset(percpu, 0, ncpus * sizeof(*percpu));
		bpf_map_update_elem(map_fd, &nid, percpu, BPF_ANY);
	}
}

static double read_io_full(void)
{
	char line[128];
	double avg10 = 0;
	FILE *f = fopen("/proc/pressure/io", "r");

	if (!f)
		return 0;
	while (fgets(line, sizeof(line), f))
		if (sscanf(line, "full avg10=%lf", &avg10) == 1)
			break;
	fclose(f);
	return avg10;
}

/* iowait as % of all CPU time since the previous call */
static double read_iowait(void)
{
	static unsigned long long prev_wait, prev_total;
	unsigned long long v[8], total = 0;
	double pct = 0;
	FILE *f = fopen("/proc/stat", "r");

	if (!f)
		return 0;
	if (fscanf(f, "cpu %llu %llu %llu %llu %llu %llu %llu %llu",
		   &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6], &v[7]) == 8) {
		for (int i = 0; i < 8; i++)
			total += v[i];
		if (total > prev_total)
			pct = 100.0 * (v[4] - prev_wait) / (total - prev_total);
		prev_wait = v[4];
		prev_total = total;
	}
	fclose(f);
	return pct;
}

static void append_node(char *list, size_t len, int nid)
{
	size_t used = strlen(list);

	snprintf(list + used, len - used, "%s%d", used ? "," : "", nid);
}

/* Advance each node's rule timers; return the verdict and the nodes behind it. */
static enum verdict evaluate(double io_full, double iowait, char *who, size_t len)
{
	bool host_stalled = io_full >= IO_FULL_MIN && iowait >= IOWAIT_MIN;
	char warn_nodes[64] = "", kill_nodes[64] = "";

	for (int i = 0; i < NUMA_MAX_NODES; i++) {
		struct node *n = &nodes[i];
		bool kswapd_stopped, thrashing;

		if (!n->online)
			continue;

		kswapd_stopped = n->kswapd_scanned < KSWAPD_IDLE && n->free_kb < n->high_kb;
		thrashing = n->file_kb < FILE_MAX_KB &&
			    n->free_kb < n->high_kb + FREE_MARGIN_KB &&
			    n->scanned >= SCAN_MIN &&
			    n->reclaimed * 100 <= n->scanned * EFF_MAX;

		n->warn_secs = kswapd_stopped ? n->warn_secs + 1 : 0;
		n->kill_secs = host_stalled && thrashing ? n->kill_secs + 1 : 0;

		if (n->kill_secs >= KILL_SECS)
			append_node(kill_nodes, sizeof(kill_nodes), i);
		else if (n->warn_secs >= WARN_SECS)
			append_node(warn_nodes, sizeof(warn_nodes), i);
	}

	if (kill_nodes[0]) {
		snprintf(who, len, "%s", kill_nodes);
		return KILL;
	}
	snprintf(who, len, "%s", warn_nodes);
	return warn_nodes[0] ? WARN : OK;
}

/* Write the state file; log the evidence whenever the verdict changes. */
static void publish(enum verdict v, const char *who, bool enforce, double io_full, double iowait)
{
	static char last[80];
	enum verdict shown = (v == KILL && !enforce) ? WARN : v;
	char now[80];
	FILE *f;

	snprintf(now, sizeof(now), "%s %s", verdict_name[v], who);
	if (!strcmp(now, last))
		return;
	snprintf(last, sizeof(last), "%s", now);

	f = fopen(STATE_FILE ".tmp", "w");
	if (f) {
		fprintf(f, "state=%s nodes=%s since=%ld\n", verdict_name[shown], who, (long)time(NULL));
		fclose(f);
		rename(STATE_FILE ".tmp", STATE_FILE);
	}

	f = fopen(EVENT_LOG, "a");
	if (!f)
		return;
	fprintf(f, "%ld verdict=%s nodes=%s dry_run=%d io_full=%.0f iowait=%.0f",
		(long)time(NULL), verdict_name[v], who, !enforce, io_full, iowait);
	for (int i = 0; i < NUMA_MAX_NODES; i++) {
		const struct node *n = &nodes[i];

		if (n->online)
			fprintf(f, " node%d:free=%lluM,high=%lluM,file=%lluM,scan=%llu,eff=%llu%%,kswapd_scan=%llu",
				i, n->free_kb >> 10, n->high_kb >> 10, n->file_kb >> 10, n->scanned,
				n->scanned ? n->reclaimed * 100 / n->scanned : 100, n->kswapd_scanned);
	}
	fprintf(f, "\n");
	fclose(f);
}

int main(int argc, char **argv)
{
	bool enforce = argc > 1 && !strcmp(argv[1], "--enforce");
	enum verdict v, prev = OK;
	struct numaguard_bpf *skel;
	struct bpf_program *prog;
	struct node_stat *percpu;
	char who[64] = "", buf[64];
	time_t kill_since = 0;
	int ncpus;

	/* Must keep running while memory thrashes: never page ourselves out. */
	if (mlockall(MCL_CURRENT | MCL_FUTURE))
		perror("mlockall");
	mkdir(RUN_DIR, 0755);
	page_kb = sysconf(_SC_PAGESIZE) / 1024;
	ncpus = libbpf_num_possible_cpus();
	percpu = calloc(ncpus, sizeof(*percpu));
	if (ncpus <= 0 || !percpu)
		return 1;

	skel = numaguard_bpf__open();
	if (!skel)
		return 1;
	/* only the per-node scan counters are needed */
	bpf_object__for_each_program(prog, skel->obj)
		if (strcmp(bpf_program__name(prog), "handle_shrink_inactive"))
			bpf_program__set_autoload(prog, false);
	if (numaguard_bpf__load(skel) || numaguard_bpf__attach(skel)) {
		fprintf(stderr, "failed to load BPF programs\n");
		numaguard_bpf__destroy(skel);
		return 1;
	}

	read_iowait();	/* first sample is the baseline */
	for (;;) {
		double io_full, iowait;
		time_t now;

		sleep(1);
		read_nodes();
		read_bpf(bpf_map__fd(skel->maps.stats), percpu, ncpus);
		io_full = read_io_full();
		iowait = read_iowait();
		v = evaluate(io_full, iowait, buf, sizeof(buf));

		now = time(NULL);
		if (prev == KILL && v != KILL && now - kill_since < KILL_HOLD_SECS)
			v = KILL;	/* give the NodeManager time to act */
		else
			snprintf(who, sizeof(who), "%s", buf);
		if (v == KILL && prev != KILL)
			kill_since = now;
		prev = v;

		publish(v, who, enforce, io_full, iowait);
	}
}
