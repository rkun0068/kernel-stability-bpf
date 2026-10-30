// SPDX-License-Identifier: GPL-2.0
/*
 * numaguard: detect the NUMA-node thrashing that precedes a host hang and
 * tell the NodeManager which node is thrashing and which containers to kill.
 * Output: /run/numaguard/state.
 *
 *   warn: a node's kswapd is idle while its free memory stays below the high
 *         watermark, for 10 minutes.
 *   kill: the host is stalled on IO (IO PSI full, iowait) and scans hard but
 *         reclaims almost nothing, and a node has no page cache left and free
 *         memory near its high watermark, for 60 seconds.
 *
 * Verdicts come from procfs, the sources (sar, atop) the thresholds came from.
 * From the first sign of trouble until all is ok again, a BPF program counts
 * pages allocated per (container, node); a kill verdict uses it to name the
 * containers to kill. Without --enforce a kill is only logged (dry run).
 */
#include <dirent.h>
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
#include "numaguard.h"
#include "numaguard.skel.h"

/* Thresholds, from 5 hangs on 4 hosts. See README.md. */
#define WARN_SECS	600
#define KILL_SECS	60
#define KILL_HOLD_SECS	300		/* keep a kill verdict at least this long */
#define KSWAPD_IDLE_PCT	1.0		/* kswapd CPU %, as atop shows it */
#define IO_FULL_MIN	80.0		/* /proc/pressure/io full avg10 */
#define IOWAIT_MIN	80.0		/* % of CPU time */
#define SCAN_MIN	600000		/* host pages scanned per second */
#define EFF_MAX		10		/* % of scanned pages reclaimed */
#define FILE_MAX_KB	(1ULL << 20)	/* node page cache below 1G */
#define FREE_MARGIN_KB	(1ULL << 20)	/* node free below high watermark + 1G */

/* Culprits */
#define CGROUP_ROOT	"/sys/fs/cgroup/yarn"	/* one directory per container */
#define SHARE_MIN_PCT	5		/* holds >= 5% of the thrashing node */
#define HIGH_PRIO_SUFFIX "-prod"	/* YARN queues killed last */
#define TOP_N		3
#define MAX_CONTAINERS	256

#define STATE_FILE	"/run/numaguard/state"
#define EVENT_LOG	"/run/numaguard/events.log"

enum verdict { OK, WARN, KILL };
static const char *verdict_name[] = { "ok", "warn", "kill" };

struct node {
	bool online;
	unsigned long long total_kb, free_kb, file_kb, high_kb;
	int kswapd_pid;
	unsigned long long kswapd_ticks;	/* utime + stime */
	double kswapd_pct;			/* over the last second */
	int warn_secs, kill_secs;		/* how long each rule held */
};

struct host {
	double io_full, iowait;
	unsigned long long scanned, reclaimed;	/* pages, last second */
};

struct container {
	char name[256];
	char queue[64];
	bool high_prio;
	unsigned long long mem_kb;		/* memory.current */
	unsigned long long node_pages;		/* allocated on the kill nodes */
	unsigned long long all_pages;		/* allocated anywhere */
	unsigned long long node_kb;		/* estimated memory on the kill nodes */
};

static struct node nodes[MAX_NODES];
static struct container containers[MAX_CONTAINERS];
static struct numaguard_bpf *skel;		/* loaded only while tracing */
static long page_kb, clk_tck;

static bool read_ull(const char *path, unsigned long long *val)
{
	FILE *f = fopen(path, "r");
	bool ok = f && fscanf(f, "%llu", val) == 1;

	if (f)
		fclose(f);
	return ok;
}

static void read_nodes(void)
{
	char path[64], line[256], key[32];
	unsigned long long val;
	int nid = -1;
	FILE *f;

	for (int i = 0; i < MAX_NODES; i++) {
		struct node *n = &nodes[i];

		snprintf(path, sizeof(path), "/sys/devices/system/node/node%d/meminfo", i);
		f = fopen(path, "r");
		n->online = f != NULL;
		n->high_kb = 0;
		while (f && fgets(line, sizeof(line), f)) {
			if (sscanf(line, "Node %*d %31[^:]: %llu", key, &val) != 2)
				continue;
			if (!strcmp(key, "MemTotal"))
				n->total_kb = val;
			else if (!strcmp(key, "MemFree"))
				n->free_kb = val;
			else if (!strcmp(key, "FilePages"))
				n->file_kb = val;
		}
		if (f)
			fclose(f);
	}

	/* a node's high watermark is the sum over its zones */
	f = fopen("/proc/zoneinfo", "r");
	while (f && fgets(line, sizeof(line), f)) {
		if (sscanf(line, "Node %d, zone", &nid) == 1)
			continue;
		if (nid >= 0 && nid < MAX_NODES && sscanf(line, " high %llu", &val) == 1)
			nodes[nid].high_kb += val * page_kb;
	}
	if (f)
		fclose(f);
}

/* kswapd threads are named "kswapd<nid>"; find their pids once at startup */
static void find_kswapds(void)
{
	char path[300], comm[32];
	struct dirent *d;
	DIR *proc = opendir("/proc");
	int nid;

	while (proc && (d = readdir(proc))) {
		FILE *f;

		snprintf(path, sizeof(path), "/proc/%s/comm", d->d_name);
		f = fopen(path, "r");
		if (!f)
			continue;
		if (fscanf(f, "%31s", comm) == 1 && sscanf(comm, "kswapd%d", &nid) == 1 &&
		    nid >= 0 && nid < MAX_NODES)
			nodes[nid].kswapd_pid = atoi(d->d_name);
		fclose(f);
	}
	if (proc)
		closedir(proc);
}

static void read_kswapds(void)
{
	char path[64], buf[512], *p;

	for (int i = 0; i < MAX_NODES; i++) {
		struct node *n = &nodes[i];
		unsigned long long utime, stime;
		FILE *f;

		if (!n->kswapd_pid)
			continue;
		snprintf(path, sizeof(path), "/proc/%d/stat", n->kswapd_pid);
		f = fopen(path, "r");
		if (!f)
			continue;
		/* skip "pid (comm) state" plus 10 fields to reach utime, stime */
		if (fgets(buf, sizeof(buf), f) && (p = strrchr(buf, ')')) &&
		    sscanf(p + 2, "%*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %llu %llu",
			   &utime, &stime) == 2) {
			if (n->kswapd_ticks)
				n->kswapd_pct = 100.0 * (utime + stime - n->kswapd_ticks) / clk_tck;
			n->kswapd_ticks = utime + stime;
		}
		fclose(f);
	}
}

static void read_host(struct host *h)
{
	static unsigned long long prev_wait, prev_total, prev_scan, prev_steal;
	unsigned long long v[8], total = 0, scan = 0, steal = 0, val;
	char line[128], key[64];
	FILE *f;

	h->io_full = 0;
	f = fopen("/proc/pressure/io", "r");
	while (f && fgets(line, sizeof(line), f))
		if (sscanf(line, "full avg10=%lf", &h->io_full) == 1)
			break;
	if (f)
		fclose(f);

	h->iowait = 0;
	f = fopen("/proc/stat", "r");
	if (f && fscanf(f, "cpu %llu %llu %llu %llu %llu %llu %llu %llu",
			&v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6], &v[7]) == 8) {
		for (int i = 0; i < 8; i++)
			total += v[i];
		if (prev_total && total > prev_total)
			h->iowait = 100.0 * (v[4] - prev_wait) / (total - prev_total);
		prev_wait = v[4];
		prev_total = total;
	}
	if (f)
		fclose(f);

	/* sar -B's pgscank + pgscand and pgsteal */
	f = fopen("/proc/vmstat", "r");
	while (f && fgets(line, sizeof(line), f)) {
		if (sscanf(line, "%63s %llu", key, &val) != 2)
			continue;
		if (!strcmp(key, "pgscan_kswapd") || !strcmp(key, "pgscan_direct"))
			scan += val;
		else if (!strcmp(key, "pgsteal_kswapd") || !strcmp(key, "pgsteal_direct"))
			steal += val;
	}
	if (f)
		fclose(f);
	h->scanned = prev_scan ? scan - prev_scan : 0;
	h->reclaimed = prev_steal ? steal - prev_steal : 0;
	prev_scan = scan;
	prev_steal = steal;
}

static void append_node(char *list, size_t len, int nid)
{
	size_t used = strlen(list);

	snprintf(list + used, len - used, "%s%d", used ? "," : "", nid);
}

/* Advance each node's rule timers; return the verdict and its nodes. */
static enum verdict evaluate(const struct host *h, char *who, size_t len)
{
	bool host_stalled = h->io_full >= IO_FULL_MIN && h->iowait >= IOWAIT_MIN &&
			    h->scanned >= SCAN_MIN && h->reclaimed * 100 <= h->scanned * EFF_MAX;
	char warn_nodes[32] = "", kill_nodes[32] = "";

	for (int i = 0; i < MAX_NODES; i++) {
		struct node *n = &nodes[i];
		bool kswapd_stopped, thrashing;

		if (!n->online)
			continue;
		kswapd_stopped = n->kswapd_pct < KSWAPD_IDLE_PCT && n->free_kb < n->high_kb;
		thrashing = n->file_kb < FILE_MAX_KB && n->free_kb < n->high_kb + FREE_MARGIN_KB;
		n->warn_secs = kswapd_stopped ? n->warn_secs + 1 : 0;
		n->kill_secs = host_stalled && thrashing ? n->kill_secs + 1 : 0;

		if (n->kill_secs >= KILL_SECS)
			append_node(kill_nodes, sizeof(kill_nodes), i);
		else if (n->warn_secs >= WARN_SECS)
			append_node(warn_nodes, sizeof(warn_nodes), i);
	}

	snprintf(who, len, "%s", kill_nodes[0] ? kill_nodes : warn_nodes);
	return kill_nodes[0] ? KILL : warn_nodes[0] ? WARN : OK;
}

/* Count allocations once any node is heading for warn or kill. */
static bool tracing_wanted(void)
{
	for (int i = 0; i < MAX_NODES; i++)
		if (nodes[i].warn_secs >= WARN_SECS || nodes[i].kill_secs > 0)
			return true;
	return false;
}

static void start_tracing(void)
{
	unsigned long long spanned = 0, start;
	char line[256];
	int nid = -1;
	FILE *f;

	skel = numaguard_bpf__open();
	if (!skel)
		return;

	/* each node's end pfn: max over its zones of start_pfn + spanned */
	f = fopen("/proc/zoneinfo", "r");
	while (f && fgets(line, sizeof(line), f)) {
		if (sscanf(line, "Node %d, zone", &nid) == 1)
			continue;
		if (sscanf(line, " spanned %llu", &spanned) == 1)
			continue;
		if (nid >= 0 && nid < MAX_NODES && sscanf(line, " start_pfn: %llu", &start) == 1 &&
		    start + spanned > skel->rodata->node_end_pfn[nid])
			skel->rodata->node_end_pfn[nid] = start + spanned;
	}
	if (f)
		fclose(f);

	if (numaguard_bpf__load(skel) || numaguard_bpf__attach(skel)) {
		numaguard_bpf__destroy(skel);
		skel = NULL;
	}
}

static void stop_tracing(void)
{
	numaguard_bpf__destroy(skel);
	skel = NULL;
}

/* Read spark.yarn.queue (only that key: the file may hold credentials). */
static void read_queue(const char *cgroup, char *queue, size_t len)
{
	char path[512], cwd[400], line[512];
	unsigned long long pid;
	ssize_t n;
	FILE *f;

	snprintf(queue, len, "-");
	snprintf(path, sizeof(path), "%s/cgroup.procs", cgroup);
	if (!read_ull(path, &pid))
		return;
	snprintf(path, sizeof(path), "/proc/%llu/cwd", pid);
	n = readlink(path, cwd, sizeof(cwd) - 1);
	if (n <= 0)
		return;
	cwd[n] = '\0';
	snprintf(path, sizeof(path), "%s/__spark_conf__/__spark_conf__.properties", cwd);
	f = fopen(path, "r");
	while (f && fgets(line, sizeof(line), f))
		if (sscanf(line, "spark.yarn.queue=%63s", queue) == 1)
			break;
	if (f)
		fclose(f);
}

/* Kill order: low priority first, then the most memory on the thrashing node. */
static bool kill_before(const struct container *a, const struct container *b)
{
	if (a->high_prio != b->high_prio)
		return !a->high_prio;
	return a->node_kb > b->node_kb;
}

/* Read one container's queue, memory.current and allocations from the map. */
static void read_container(struct container *c, const char *name, __u32 cgid, int map_fd)
{
	unsigned long long key, *prev = NULL, cur, pages;
	char path[320];
	size_t q;

	memset(c, 0, sizeof(*c));
	snprintf(c->name, sizeof(c->name), "%s", name);

	snprintf(path, sizeof(path), CGROUP_ROOT "/%s", name);
	read_queue(path, c->queue, sizeof(c->queue));
	q = strlen(c->queue);
	c->high_prio = q >= strlen(HIGH_PRIO_SUFFIX) &&
		       !strcmp(c->queue + q - strlen(HIGH_PRIO_SUFFIX), HIGH_PRIO_SUFFIX);

	snprintf(path, sizeof(path), CGROUP_ROOT "/%s/memory.current", name);
	read_ull(path, &c->mem_kb);
	c->mem_kb >>= 10;

	/* map keys are (cgroup id << 8 | node); 5.4 cgroup ids fit in 32 bits */
	while (!bpf_map_get_next_key(map_fd, prev, &key)) {
		cur = key;
		prev = &cur;
		if ((__u32)(key >> 8) != cgid || bpf_map_lookup_elem(map_fd, &key, &pages))
			continue;
		c->all_pages += pages;
		if (nodes[key & 0xff].kill_secs >= KILL_SECS)
			c->node_pages += pages;
	}
}

/*
 * Name the containers to kill:
 *   1. on the thrashing node: it allocated pages there (BPF);
 *   2. a large share of it: >= SHARE_MIN_PCT, estimated as memory.current x
 *      its share of allocations made there (5.4 has no per-node memory per
 *      cgroup; memory.current keeps page-cache churn from looking big);
 *   3. low priority first, then the most memory on the node.
 */
static void find_culprits(char *out, size_t len)
{
	struct container *top[TOP_N] = {};
	unsigned long long kill_kb = 0;
	char path[320];
	struct dirent *d;
	struct stat st;
	DIR *dir = opendir(CGROUP_ROOT);
	int n = 0;
	size_t used = 0;

	for (int i = 0; i < MAX_NODES; i++)
		if (nodes[i].kill_secs >= KILL_SECS)
			kill_kb += nodes[i].total_kb;

	/* one cgroup directory per container; its inode is its cgroup id */
	while (dir && n < MAX_CONTAINERS && (d = readdir(dir))) {
		snprintf(path, sizeof(path), CGROUP_ROOT "/%s", d->d_name);
		if (d->d_name[0] != '.' && !stat(path, &st))
			read_container(&containers[n++], d->d_name, st.st_ino,
				       bpf_map__fd(skel->maps.allocs));
	}
	if (dir)
		closedir(dir);

	for (int i = 0; i < n; i++) {
		struct container *c = &containers[i];

		if (!c->node_pages)
			continue;					/* 1 */
		c->node_kb = c->mem_kb * c->node_pages / c->all_pages;
		if (c->node_kb * 100 < kill_kb * SHARE_MIN_PCT)
			continue;					/* 2 */
		for (int t = 0; t < TOP_N; t++) {
			if (top[t] && !kill_before(c, top[t]))
				continue;
			memmove(&top[t + 1], &top[t], (TOP_N - t - 1) * sizeof(top[0]));
			top[t] = c;					/* 3 */
			break;
		}
	}

	out[0] = '\0';
	for (int t = 0; t < TOP_N && top[t] && used < len; t++)
		used += snprintf(out + used, len - used, "%s%s(queue=%s,%s,node=%lluM)",
				 used ? "," : "", top[t]->name, top[t]->queue,
				 top[t]->high_prio ? "high" : "low", top[t]->node_kb >> 10);
}

/* Write the state file; log the evidence whenever the verdict changes. */
static void publish(enum verdict v, const char *who, const char *culprits, bool enforce,
		    const struct host *h)
{
	static char last[1024];
	enum verdict shown = (v == KILL && !enforce) ? WARN : v;
	char now[1024];
	FILE *f;

	snprintf(now, sizeof(now), "%s %s %s", verdict_name[v], who, culprits);
	if (!strcmp(now, last))
		return;
	snprintf(last, sizeof(last), "%s", now);

	f = fopen(STATE_FILE ".tmp", "w");
	if (f) {
		fprintf(f, "state=%s nodes=%s culprits=%s since=%ld\n", verdict_name[shown], who,
			shown == KILL ? culprits : "", (long)time(NULL));
		fclose(f);
		rename(STATE_FILE ".tmp", STATE_FILE);
	}

	f = fopen(EVENT_LOG, "a");
	if (!f)
		return;
	fprintf(f, "%ld verdict=%s nodes=%s culprits=%s dry_run=%d io_full=%.0f iowait=%.0f scan=%llu eff=%llu%%",
		(long)time(NULL), verdict_name[v], who, culprits, !enforce, h->io_full, h->iowait,
		h->scanned, h->scanned ? h->reclaimed * 100 / h->scanned : 100);
	for (int i = 0; i < MAX_NODES; i++)
		if (nodes[i].online)
			fprintf(f, " node%d:free=%lluM,high=%lluM,file=%lluM,kswapd=%.0f%%", i,
				nodes[i].free_kb >> 10, nodes[i].high_kb >> 10,
				nodes[i].file_kb >> 10, nodes[i].kswapd_pct);
	fprintf(f, "\n");
	fclose(f);
}

int main(int argc, char **argv)
{
	bool enforce = argc > 1 && !strcmp(argv[1], "--enforce");
	char who[32] = "", buf[32], culprits[600] = "";
	enum verdict v, prev = OK;
	time_t now, kill_since = 0;
	struct host h;

	/* Must keep running while memory thrashes: never page ourselves out. */
	if (mlockall(MCL_CURRENT | MCL_FUTURE))
		perror("mlockall");
	mkdir("/run/numaguard", 0755);
	page_kb = sysconf(_SC_PAGESIZE) / 1024;
	clk_tck = sysconf(_SC_CLK_TCK);
	find_kswapds();

	for (;;) {
		read_nodes();
		read_kswapds();
		read_host(&h);
		v = evaluate(&h, buf, sizeof(buf));
		now = time(NULL);

		if (!skel && tracing_wanted())
			start_tracing();

		if (prev == KILL && v != KILL && now - kill_since < KILL_HOLD_SECS) {
			v = KILL;		/* give the NodeManager time to act */
		} else {
			snprintf(who, sizeof(who), "%s", buf);
			if (v != KILL)
				culprits[0] = '\0';
			else if (prev != KILL && skel)	/* rank once, when kill starts */
				find_culprits(culprits, sizeof(culprits));
		}
		if (v == KILL && prev != KILL)
			kill_since = now;
		prev = v;

		if (skel && v == OK && !tracing_wanted())
			stop_tracing();

		publish(v, who, culprits, enforce, &h);
		sleep(1);
	}
}
