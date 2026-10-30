// SPDX-License-Identifier: GPL-2.0
/*
 * numaguard: detect the NUMA-node thrashing that precedes a host hang and
 * publish a verdict for the NodeManager in /run/numaguard/state.
 *
 *   warn: a node's kswapd is idle while the node's free memory stays below
 *         its high watermark, for 10 minutes.
 *   kill: the host is stalled on IO (IO PSI full and iowait), the host scans
 *         hard but reclaims almost nothing, and a node has no page cache left
 *         and free memory near its high watermark, for 60 seconds.
 *
 * Reads procfs/sysfs only (no BPF), the same sources as sar and atop that the
 * thresholds come from. Without --enforce (dry run) a kill verdict is only
 * logged; the state file says warn.
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

/* Thresholds, from 5 hangs on 4 hosts. See README.md. */
#define WARN_SECS	600
#define KILL_SECS	60
#define KILL_HOLD_SECS	300		/* keep a kill verdict at least this long */
#define IO_FULL_MIN	80.0		/* /proc/pressure/io full avg10 */
#define IOWAIT_MIN	80.0		/* % of CPU time */
#define SCAN_MIN	600000		/* host pages scanned per second */
#define EFF_MAX		10		/* % of scanned pages reclaimed */
#define FILE_MAX_KB	(1ULL << 20)	/* node page cache below 1G */
#define FREE_MARGIN_KB	(1ULL << 20)	/* node free below high watermark + 1G */
#define KSWAPD_IDLE_PCT	1.0		/* kswapd CPU %, as atop shows it */

#define MAX_NODES	64
#define RUN_DIR		"/run/numaguard"
#define STATE_FILE	RUN_DIR "/state"
#define EVENT_LOG	RUN_DIR "/events.log"

enum verdict { OK, WARN, KILL };
static const char *verdict_name[] = { "ok", "warn", "kill" };

struct node {
	bool online;
	unsigned long long free_kb, file_kb, high_kb;
	int kswapd_pid;
	unsigned long long kswapd_ticks;	/* utime + stime, cumulative */
	double kswapd_pct;			/* CPU % over the last second */
	int warn_secs, kill_secs;		/* how long each rule held */
};

/* host-wide, over the last second */
struct host {
	double io_full, iowait;
	unsigned long long scanned, reclaimed;
};

static struct node nodes[MAX_NODES];
static long page_kb, clk_tck;

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
		if (nid >= 0 && nid < MAX_NODES && sscanf(line, " high %llu", &val) == 1)
			nodes[nid].high_kb += val * page_kb;
	}
	fclose(f);
}

/* kswapd threads are named "kswapd<nid>"; find their pids once at startup */
static void find_kswapds(void)
{
	char path[64], comm[32];
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
		unsigned long long utime, stime, ticks;
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
			ticks = utime + stime;
			if (n->kswapd_ticks)
				n->kswapd_pct = 100.0 * (ticks - n->kswapd_ticks) / clk_tck;
			n->kswapd_ticks = ticks;
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
	if (f) {
		while (fgets(line, sizeof(line), f))
			if (sscanf(line, "full avg10=%lf", &h->io_full) == 1)
				break;
		fclose(f);
	}

	h->iowait = 0;
	f = fopen("/proc/stat", "r");
	if (f) {
		if (fscanf(f, "cpu %llu %llu %llu %llu %llu %llu %llu %llu",
			   &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6], &v[7]) == 8) {
			for (int i = 0; i < 8; i++)
				total += v[i];
			if (prev_total && total > prev_total)
				h->iowait = 100.0 * (v[4] - prev_wait) / (total - prev_total);
			prev_wait = v[4];
			prev_total = total;
		}
		fclose(f);
	}

	/* sar -B's pgscank+pgscand and pgsteal */
	f = fopen("/proc/vmstat", "r");
	if (f) {
		while (fgets(line, sizeof(line), f)) {
			if (sscanf(line, "%63s %llu", key, &val) != 2)
				continue;
			if (!strcmp(key, "pgscan_kswapd") || !strcmp(key, "pgscan_direct"))
				scan += val;
			else if (!strcmp(key, "pgsteal_kswapd") || !strcmp(key, "pgsteal_direct"))
				steal += val;
		}
		fclose(f);
		h->scanned = prev_scan ? scan - prev_scan : 0;
		h->reclaimed = prev_steal ? steal - prev_steal : 0;
		prev_scan = scan;
		prev_steal = steal;
	}
}

static void append_node(char *list, size_t len, int nid)
{
	size_t used = strlen(list);

	snprintf(list + used, len - used, "%s%d", used ? "," : "", nid);
}

/* Advance each node's rule timers; return the verdict and the nodes behind it. */
static enum verdict evaluate(const struct host *h, char *who, size_t len)
{
	bool host_stalled = h->io_full >= IO_FULL_MIN && h->iowait >= IOWAIT_MIN &&
			    h->scanned >= SCAN_MIN &&
			    h->reclaimed * 100 <= h->scanned * EFF_MAX;
	char warn_nodes[64] = "", kill_nodes[64] = "";

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

	if (kill_nodes[0]) {
		snprintf(who, len, "%s", kill_nodes);
		return KILL;
	}
	snprintf(who, len, "%s", warn_nodes);
	return warn_nodes[0] ? WARN : OK;
}

/* Write the state file; log the evidence whenever the verdict changes. */
static void publish(enum verdict v, const char *who, bool enforce, const struct host *h)
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
	fprintf(f, "%ld verdict=%s nodes=%s dry_run=%d io_full=%.0f iowait=%.0f scan=%llu eff=%llu%%",
		(long)time(NULL), verdict_name[v], who, !enforce, h->io_full, h->iowait, h->scanned,
		h->scanned ? h->reclaimed * 100 / h->scanned : 100);
	for (int i = 0; i < MAX_NODES; i++) {
		const struct node *n = &nodes[i];

		if (n->online)
			fprintf(f, " node%d:free=%lluM,high=%lluM,file=%lluM,kswapd=%.0f%%",
				i, n->free_kb >> 10, n->high_kb >> 10, n->file_kb >> 10, n->kswapd_pct);
	}
	fprintf(f, "\n");
	fclose(f);
}

int main(int argc, char **argv)
{
	bool enforce = argc > 1 && !strcmp(argv[1], "--enforce");
	enum verdict v, prev = OK;
	char who[64] = "", buf[64];
	time_t kill_since = 0;
	struct host h;

	/* Must keep running while memory thrashes: never page ourselves out. */
	if (mlockall(MCL_CURRENT | MCL_FUTURE))
		perror("mlockall");
	mkdir(RUN_DIR, 0755);
	page_kb = sysconf(_SC_PAGESIZE) / 1024;
	clk_tck = sysconf(_SC_CLK_TCK);
	find_kswapds();

	for (;;) {
		time_t now;

		read_nodes();
		read_kswapds();
		read_host(&h);
		v = evaluate(&h, buf, sizeof(buf));

		now = time(NULL);
		if (prev == KILL && v != KILL && now - kill_since < KILL_HOLD_SECS)
			v = KILL;	/* give the NodeManager time to act */
		else
			snprintf(who, sizeof(who), "%s", buf);
		if (v == KILL && prev != KILL)
			kill_since = now;
		prev = v;

		publish(v, who, enforce, &h);
		sleep(1);
	}
}
