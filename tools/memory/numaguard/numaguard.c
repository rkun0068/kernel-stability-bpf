// SPDX-License-Identifier: GPL-2.0
/*
 * numaguard: a rule-driven guard. Every second it samples host and per-node
 * metrics from procfs and sysfs, checks the rules in the rules directory
 * (default /etc/numaguard/rules.d, reread on SIGHUP), and acts on the rules
 * whose conditions held long enough. See README.md for the rule format.
 *
 * Actions: warn (write the state file), exec (run a script), kill (name the
 * containers to kill in the state file; the NodeManager kills them). While a
 * kill rule's conditions hold, a BPF program counts pages allocated per
 * (container, node), so the culprits on the matching nodes can be named.
 *
 * Output: /run/numaguard/state (active rules), /run/numaguard/events.log.
 */
#include <dirent.h>
#include <fnmatch.h>
#include <signal.h>
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

#define RULES_DIR	"/etc/numaguard/rules.d"
#define STATE_FILE	"/run/numaguard/state"
#define EVENT_LOG	"/run/numaguard/events.log"

#define MAX_FILES	16
#define MAX_RULES	64
#define MAX_CONDS	8
#define MAX_CONTAINERS	256
#define SHARE_MIN_PCT	5		/* a culprit holds >= 5% of the matching nodes */
#define EXEC_TIMEOUT	30		/* seconds an exec action may run */

/* Metrics. Memory is in bytes, so rules can say 1G. */
enum { H_PSI_CPU_SOME, H_PSI_MEM_SOME, H_PSI_MEM_FULL, H_PSI_IO_SOME, H_PSI_IO_FULL,
       H_IOWAIT, H_SCAN, H_EFF, NR_HOST };
static const char *host_names[NR_HOST] = {
	"psi.cpu.some", "psi.mem.some", "psi.mem.full", "psi.io.some", "psi.io.full",
	"iowait",	/* % of CPU time */
	"scan",		/* pages scanned per second (sar -B pgscank + pgscand) */
	"eff",		/* % of scanned pages reclaimed */
};
enum { N_FREE, N_FILE, N_HIGH, N_FREE_OVER_HIGH, N_KSWAPD, NR_NODE };
static const char *node_names[NR_NODE] = {
	"free", "file",
	"high",			/* high watermark, summed over the node's zones */
	"free_over_high",	/* free - high; negative below the watermark */
	"kswapd",		/* kswapd CPU %, as atop shows it */
};

static double host_val[NR_HOST];
static double node_val[MAX_NODES][NR_NODE];
static double node_total[MAX_NODES];
static unsigned online_mask;

/* Rules. One rules_file per file; its rules point back to it. */
enum op { LT, LE, GT, GE };
enum action { WARN, EXEC, KILL };
static const char *action_name[] = { "warn", "exec", "kill" };

struct rules_file {
	char scope[256];	/* one cgroup directory per container */
	char prio_file[256];	/* in the container's working directory */
	char prio_key[64];
	char prio_high[64];	/* glob: values that are high priority */
	bool enforce;		/* otherwise dry run: kill and exec are only logged */
};

struct cond {
	bool node;
	int metric;
	enum op op;
	double val;
};

struct rule {
	char name[64];
	struct rules_file *file;
	struct cond conds[MAX_CONDS];
	int nconds;
	bool per_node;		/* has node conditions: checked for each node */
	int for_secs;
	enum action action;
	char exec[256];
	int top, cooldown;

	int held[MAX_NODES];	/* seconds the conditions held; [0] if not per node */
	bool active;
	time_t since, acted;
	char nodes[32], culprits[600];
};

struct container {
	char name[256];
	char prio[64];
	bool high_prio;
	unsigned long long mem;		/* memory.current */
	unsigned long long node_pages;	/* allocated on the matching nodes */
	unsigned long long all_pages;	/* allocated anywhere */
	unsigned long long node_mem;	/* estimated memory on the matching nodes */
};

static struct rules_file files[MAX_FILES];
static struct rule rules[MAX_RULES];
static int nfiles, nrules;
static struct container containers[MAX_CONTAINERS];
static int kswapd_pid[MAX_NODES];
static unsigned long long kswapd_ticks[MAX_NODES];
static struct numaguard_bpf *skel;	/* loaded only while a kill rule needs it */
static long page_size, clk_tck;
static volatile sig_atomic_t reload;

/* ---- sampling ---- */

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

	online_mask = 0;
	for (int i = 0; i < MAX_NODES; i++) {
		snprintf(path, sizeof(path), "/sys/devices/system/node/node%d/meminfo", i);
		f = fopen(path, "r");
		if (!f)
			continue;
		online_mask |= 1u << i;
		node_val[i][N_HIGH] = 0;
		while (fgets(line, sizeof(line), f)) {
			if (sscanf(line, "Node %*d %31[^:]: %llu", key, &val) != 2)
				continue;
			if (!strcmp(key, "MemTotal"))
				node_total[i] = val * 1024.0;
			else if (!strcmp(key, "MemFree"))
				node_val[i][N_FREE] = val * 1024.0;
			else if (!strcmp(key, "FilePages"))
				node_val[i][N_FILE] = val * 1024.0;
		}
		fclose(f);
	}

	f = fopen("/proc/zoneinfo", "r");
	while (f && fgets(line, sizeof(line), f)) {
		if (sscanf(line, "Node %d, zone", &nid) == 1)
			continue;
		if (nid >= 0 && nid < MAX_NODES && sscanf(line, " high %llu", &val) == 1)
			node_val[nid][N_HIGH] += (double)val * page_size;
	}
	if (f)
		fclose(f);

	for (int i = 0; i < MAX_NODES; i++)
		node_val[i][N_FREE_OVER_HIGH] = node_val[i][N_FREE] - node_val[i][N_HIGH];
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
			kswapd_pid[nid] = atoi(d->d_name);
		fclose(f);
	}
	if (proc)
		closedir(proc);
}

static void read_kswapds(void)
{
	char path[64], buf[512], *p;

	for (int i = 0; i < MAX_NODES; i++) {
		unsigned long long utime, stime;
		FILE *f;

		if (!kswapd_pid[i])
			continue;
		snprintf(path, sizeof(path), "/proc/%d/stat", kswapd_pid[i]);
		f = fopen(path, "r");
		if (!f)
			continue;
		/* skip "pid (comm) state" plus 10 fields to reach utime, stime */
		if (fgets(buf, sizeof(buf), f) && (p = strrchr(buf, ')')) &&
		    sscanf(p + 2, "%*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %llu %llu",
			   &utime, &stime) == 2) {
			if (kswapd_ticks[i])
				node_val[i][N_KSWAPD] = 100.0 * (utime + stime - kswapd_ticks[i]) / clk_tck;
			kswapd_ticks[i] = utime + stime;
		}
		fclose(f);
	}
}

/* avg10 of /proc/pressure/<res>; full < 0 if the kernel has no "full" line */
static void read_psi(const char *res, int some, int full)
{
	char path[64], line[256];
	double v;
	FILE *f;

	snprintf(path, sizeof(path), "/proc/pressure/%s", res);
	host_val[some] = 0;
	if (full >= 0)
		host_val[full] = 0;
	f = fopen(path, "r");
	while (f && fgets(line, sizeof(line), f)) {
		if (sscanf(line, "some avg10=%lf", &v) == 1)
			host_val[some] = v;
		else if (full >= 0 && sscanf(line, "full avg10=%lf", &v) == 1)
			host_val[full] = v;
	}
	if (f)
		fclose(f);
}

static void read_host(void)
{
	static unsigned long long prev_wait, prev_total, prev_scan, prev_steal;
	unsigned long long v[8], total = 0, scan = 0, steal = 0, val;
	char line[128], key[64];
	FILE *f;

	read_psi("cpu", H_PSI_CPU_SOME, -1);
	read_psi("memory", H_PSI_MEM_SOME, H_PSI_MEM_FULL);
	read_psi("io", H_PSI_IO_SOME, H_PSI_IO_FULL);

	host_val[H_IOWAIT] = 0;
	f = fopen("/proc/stat", "r");
	if (f && fscanf(f, "cpu %llu %llu %llu %llu %llu %llu %llu %llu",
			&v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6], &v[7]) == 8) {
		for (int i = 0; i < 8; i++)
			total += v[i];
		if (prev_total && total > prev_total)
			host_val[H_IOWAIT] = 100.0 * (v[4] - prev_wait) / (total - prev_total);
		prev_wait = v[4];
		prev_total = total;
	}
	if (f)
		fclose(f);

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
	host_val[H_SCAN] = prev_scan ? scan - prev_scan : 0;
	host_val[H_EFF] = host_val[H_SCAN] ? 100.0 * (steal - prev_steal) / host_val[H_SCAN] : 100;
	prev_scan = scan;
	prev_steal = steal;
}

/* ---- rules files ---- */

static int lookup(const char **names, int n, const char *name)
{
	for (int i = 0; i < n; i++)
		if (!strcmp(names[i], name))
			return i;
	return -1;
}

/* "80", "1G", "-512M" */
static bool parse_value(const char *s, double *val)
{
	char *end;

	*val = strtod(s, &end);
	switch (*end) {
	case 'G': *val *= 1024;		/* fall through */
	case 'M': *val *= 1024;		/* fall through */
	case 'K': *val *= 1024; end++;
	}
	return end != s && !*end;
}

/* "60s", "10m" */
static bool parse_secs(const char *s, int *secs)
{
	char *end;

	*secs = strtol(s, &end, 10);
	if (*end == 'm')
		*secs *= 60;
	return end != s && (!*end || !strcmp(end, "s") || !strcmp(end, "m"));
}

/* when <scope.metric> <op> <value> ... [for <time>] */
static bool parse_when(struct rule *r, char **tok, int n)
{
	static const char *ops[] = { "<", "<=", ">", ">=" };

	for (int i = 0; i < n; i += 3) {
		struct cond *c = &r->conds[r->nconds];

		if (!strcmp(tok[i], "for") && i + 1 < n) {
			if (!parse_secs(tok[i + 1], &r->for_secs))
				return false;
			i--;
			continue;
		}
		if (i + 2 >= n || r->nconds == MAX_CONDS)
			return false;
		if (!strncmp(tok[i], "host.", 5))
			c->metric = lookup(host_names, NR_HOST, tok[i] + 5);
		else if (!strncmp(tok[i], "node.", 5))
			c->metric = lookup(node_names, NR_NODE, tok[i] + 5), c->node = true;
		else
			return false;
		c->op = lookup(ops, 4, tok[i + 1]);
		if (c->metric < 0 || (int)c->op < 0 || !parse_value(tok[i + 2], &c->val))
			return false;
		r->per_node |= c->node;
		r->nconds++;
	}
	return true;
}

/* do warn | exec <path> | kill [top=N] ... [cooldown=<time>] */
static bool parse_do(struct rule *r, char **tok, int n)
{
	int i = 1;

	if (!strcmp(tok[0], "warn"))
		r->action = WARN;
	else if (!strcmp(tok[0], "kill"))
		r->action = KILL;
	else if (!strcmp(tok[0], "exec") && n > 1)
		r->action = EXEC, snprintf(r->exec, sizeof(r->exec), "%s", tok[i++]);
	else
		return false;
	for (; i < n; i++)
		if (!(r->action == KILL && sscanf(tok[i], "top=%d", &r->top) == 1) &&
		    !(!strncmp(tok[i], "cooldown=", 9) && parse_secs(tok[i] + 9, &r->cooldown)))
			return false;
	return true;
}

/* prio file=<path> key=<key> high=<glob> */
static bool parse_prio(struct rules_file *rf, char **tok, int n)
{
	for (int i = 0; i < n; i++)
		if (sscanf(tok[i], "file=%255s", rf->prio_file) != 1 &&
		    sscanf(tok[i], "key=%63s", rf->prio_key) != 1 &&
		    sscanf(tok[i], "high=%63s", rf->prio_high) != 1)
			return false;
	return rf->prio_file[0] && rf->prio_key[0];
}

/* Load one file; on any error drop the whole file and say where. */
static void load_file(const char *path)
{
	struct rules_file *rf = &files[nfiles];
	int first = nrules, lineno = 0;
	struct rule *r = NULL;
	char line[512], *tok[32], *p;
	FILE *f;
	bool ok;

	if (nfiles == MAX_FILES)
		return;
	f = fopen(path, "r");
	ok = f != NULL;
	memset(rf, 0, sizeof(*rf));
	while (ok && fgets(line, sizeof(line), f)) {
		int n = 0;

		lineno++;
		if ((p = strchr(line, '#')))
			*p = '\0';
		for (p = strtok(line, " \t\n"); p && n < 32; p = strtok(NULL, " \t\n"))
			tok[n++] = p;
		if (!n)
			continue;
		if (!strcmp(tok[0], "scope") && n == 2)
			snprintf(rf->scope, sizeof(rf->scope), "%s", tok[1]);
		else if (!strcmp(tok[0], "mode") && n == 2 &&
			 (!strcmp(tok[1], "dry") || !strcmp(tok[1], "enforce")))
			rf->enforce = !strcmp(tok[1], "enforce");
		else if (!strcmp(tok[0], "prio"))
			ok = parse_prio(rf, tok + 1, n - 1);
		else if (!strcmp(tok[0], "rule") && n == 2 && nrules < MAX_RULES) {
			r = &rules[nrules++];
			memset(r, 0, sizeof(*r));
			snprintf(r->name, sizeof(r->name), "%s", tok[1]);
			r->file = rf;
			r->for_secs = 1;
			r->action = -1;
			r->top = 3;
		} else if (!strcmp(tok[0], "when") && r)
			ok = parse_when(r, tok + 1, n - 1);
		else if (!strcmp(tok[0], "do") && r && n > 1)
			ok = parse_do(r, tok + 1, n - 1);
		else
			ok = false;
	}
	for (int i = first; ok && i < nrules; i++)
		ok = rules[i].nconds && (int)rules[i].action >= 0 &&
		     (rules[i].action != KILL || rf->scope[0]);
	if (f)
		fclose(f);
	if (!ok) {
		fprintf(stderr, "%s:%d: bad rules file, ignored\n", path, lineno);
		nrules = first;
		return;
	}
	nfiles++;
}

static int is_rules_file(const struct dirent *d)
{
	size_t n = strlen(d->d_name);

	return n > 6 && !strcmp(d->d_name + n - 6, ".rules");
}

static void load_rules(const char *dir)
{
	struct dirent **list;
	char path[512];
	int n = scandir(dir, &list, is_rules_file, alphasort);

	nfiles = nrules = 0;
	for (int i = 0; i < n; i++) {
		snprintf(path, sizeof(path), "%s/%s", dir, list[i]->d_name);
		load_file(path);
		free(list[i]);
	}
	if (n >= 0)
		free(list);
	fprintf(stderr, "loaded %d rules from %d files in %s\n", nrules, nfiles, dir);
}

/* ---- culprits (BPF) ---- */

static bool tracing_wanted(void)
{
	for (int i = 0; i < nrules; i++) {
		if (rules[i].action != KILL)
			continue;
		if (rules[i].active)
			return true;
		for (int n = 0; n < MAX_NODES; n++)
			if (rules[i].held[n])
				return true;
	}
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

/* Read the priority key (only that key: the file may hold credentials). */
static void read_prio(const struct rules_file *rf, const char *cgroup, char *out, size_t len)
{
	char path[700], cwd[400], line[512];
	size_t klen = strlen(rf->prio_key);
	unsigned long long pid;
	ssize_t n;
	FILE *f;

	snprintf(out, len, "-");
	snprintf(path, sizeof(path), "%s/cgroup.procs", cgroup);
	if (!rf->prio_file[0] || !read_ull(path, &pid))
		return;
	snprintf(path, sizeof(path), "/proc/%llu/cwd", pid);
	n = readlink(path, cwd, sizeof(cwd) - 1);
	if (n <= 0)
		return;
	cwd[n] = '\0';
	snprintf(path, sizeof(path), "%s/%s", cwd, rf->prio_file);
	f = fopen(path, "r");
	while (f && fgets(line, sizeof(line), f))
		if (!strncmp(line, rf->prio_key, klen) && line[klen] == '=' &&
		    sscanf(line + klen + 1, "%63s", out) == 1)
			break;
	if (f)
		fclose(f);
}

/* Read one container's priority, memory.current and allocations from the map. */
static void read_container(struct container *c, const struct rules_file *rf, const char *name,
			   __u32 cgid, unsigned mask, int map_fd)
{
	unsigned long long key, *prev = NULL, cur, pages;
	char path[600];

	memset(c, 0, sizeof(*c));
	snprintf(c->name, sizeof(c->name), "%s", name);

	snprintf(path, sizeof(path), "%s/%s", rf->scope, name);
	read_prio(rf, path, c->prio, sizeof(c->prio));
	c->high_prio = rf->prio_high[0] && !fnmatch(rf->prio_high, c->prio, 0);

	snprintf(path, sizeof(path), "%s/%s/memory.current", rf->scope, name);
	read_ull(path, &c->mem);

	/* map keys are (cgroup id << 8 | node); 5.4 cgroup ids fit in 32 bits */
	while (!bpf_map_get_next_key(map_fd, prev, &key)) {
		cur = key;
		prev = &cur;
		if ((__u32)(key >> 8) != cgid || bpf_map_lookup_elem(map_fd, &key, &pages))
			continue;
		c->all_pages += pages;
		if (mask & (1u << (key & 0xff)))
			c->node_pages += pages;
	}
}

/* Kill order: low priority first, then the most memory on the matching nodes. */
static bool kill_before(const struct container *a, const struct container *b)
{
	if (a->high_prio != b->high_prio)
		return !a->high_prio;
	return a->node_mem > b->node_mem;
}

/*
 * Name the containers to kill:
 *   1. on the matching nodes: it allocated pages there (BPF);
 *   2. a large share of them: >= SHARE_MIN_PCT, estimated as memory.current x
 *      its share of allocations made there (5.4 has no per-node memory per
 *      cgroup; memory.current keeps page-cache churn from looking big);
 *   3. low priority first, then the most memory on the nodes.
 */
static void find_culprits(struct rule *r, unsigned mask)
{
	const struct rules_file *rf = r->file;
	struct container *top[MAX_CONTAINERS] = {};
	double nodes_mem = 0;
	char path[600];
	struct dirent *d;
	struct stat st;
	DIR *dir;
	int n = 0, ntop = r->top < MAX_CONTAINERS ? r->top : MAX_CONTAINERS;
	size_t used = 0;

	if (!skel)
		return;
	for (int i = 0; i < MAX_NODES; i++)
		if (mask & (1u << i))
			nodes_mem += node_total[i];

	/* one cgroup directory per container; its inode is its cgroup id */
	dir = opendir(rf->scope);
	while (dir && n < MAX_CONTAINERS && (d = readdir(dir))) {
		snprintf(path, sizeof(path), "%s/%s", rf->scope, d->d_name);
		if (d->d_name[0] != '.' && !stat(path, &st) && S_ISDIR(st.st_mode))
			read_container(&containers[n++], rf, d->d_name, st.st_ino, mask,
				       bpf_map__fd(skel->maps.allocs));
	}
	if (dir)
		closedir(dir);

	for (int i = 0; i < n; i++) {
		struct container *c = &containers[i];

		if (!c->node_pages)
			continue;					/* 1 */
		c->node_mem = (double)c->mem * c->node_pages / c->all_pages;
		if (c->node_mem * 100.0 < nodes_mem * SHARE_MIN_PCT)
			continue;					/* 2 */
		for (int t = 0; t < ntop; t++) {
			if (top[t] && !kill_before(c, top[t]))
				continue;
			memmove(&top[t + 1], &top[t], (ntop - t - 1) * sizeof(top[0]));
			top[t] = c;					/* 3 */
			break;
		}
	}

	for (int t = 0; t < ntop && top[t] && used < sizeof(r->culprits); t++)
		used += snprintf(r->culprits + used, sizeof(r->culprits) - used,
				 "%s%s(prio=%s,%s,node=%lluM)", used ? "," : "", top[t]->name,
				 top[t]->prio, top[t]->high_prio ? "high" : "low",
				 top[t]->node_mem >> 20);
}

/* ---- actions and output ---- */

static void log_event(const struct rule *r, const char *event)
{
	FILE *f = fopen(EVENT_LOG, "a");

	if (!f)
		return;
	fprintf(f, "%ld rule=%s event=%s action=%s dry_run=%d nodes=%s culprits=%s",
		(long)time(NULL), r->name, event, action_name[r->action], !r->file->enforce,
		r->nodes, r->culprits);
	for (int i = 0; i < NR_HOST; i++)
		fprintf(f, " %s=%.0f", host_names[i], host_val[i]);
	for (int i = 0; i < MAX_NODES; i++)
		if (online_mask & (1u << i))
			fprintf(f, " node%d:free=%.0fM,high=%.0fM,file=%.0fM,kswapd=%.0f%%", i,
				node_val[i][N_FREE] / (1 << 20), node_val[i][N_HIGH] / (1 << 20),
				node_val[i][N_FILE] / (1 << 20), node_val[i][N_KSWAPD]);
	fprintf(f, "\n");
	fclose(f);
}

/* Run the rule's script in the background with its context in GUARD_*. */
static void run(const struct rule *r)
{
	if (fork())
		return;
	setenv("GUARD_RULE", r->name, 1);
	setenv("GUARD_NODES", r->nodes, 1);
	alarm(EXEC_TIMEOUT);			/* survives exec; SIGALRM kills it */
	execl(r->exec, r->exec, (char *)NULL);
	_exit(127);
}

static void act(struct rule *r, unsigned mask, time_t now, const char *event)
{
	size_t used = 0;

	r->acted = now;
	r->nodes[0] = r->culprits[0] = '\0';
	for (int i = 0; i < MAX_NODES; i++)
		if (mask & (1u << i))
			used += snprintf(r->nodes + used, sizeof(r->nodes) - used, "%s%d",
					 used ? "," : "", i);
	if (r->action == KILL)
		find_culprits(r, mask);
	else if (r->action == EXEC && r->file->enforce)
		run(r);
	log_event(r, event);
}

/*
 * Advance a rule by one second. It fires when its conditions have held for
 * for_secs (on some node, if it has node conditions). Once fired it stays
 * active for at least cooldown seconds, giving the NodeManager time to act,
 * and acts again every cooldown seconds while the conditions still hold.
 */
static void step(struct rule *r, time_t now)
{
	unsigned mask = 0;

	for (int i = 0; i < (r->per_node ? MAX_NODES : 1); i++) {
		bool holds = !r->per_node || (online_mask & (1u << i));

		for (int c = 0; holds && c < r->nconds; c++) {
			const struct cond *k = &r->conds[c];
			double v = k->node ? node_val[i][k->metric] : host_val[k->metric];

			holds = k->op == LT ? v < k->val : k->op == LE ? v <= k->val :
				k->op == GT ? v > k->val : v >= k->val;
		}
		r->held[i] = holds ? r->held[i] + 1 : 0;
		if (r->held[i] >= r->for_secs)
			mask |= 1u << i;
	}
	if (mask && !r->per_node)
		mask = online_mask;

	if (mask && !r->active) {
		r->active = true;
		r->since = now;
		act(r, mask, now, "fire");
	} else if (mask && r->cooldown && now - r->acted >= r->cooldown) {
		act(r, mask, now, "again");
	} else if (!mask && r->active && now - r->acted >= r->cooldown) {
		r->active = false;
		log_event(r, "clear");
	}
}

/* One line per active rule. A dry-run kill is shown as warn, without culprits. */
static void write_state(void)
{
	static char last[8192] = "-";
	char buf[sizeof(last)];
	size_t used = 0;
	FILE *f;

	buf[0] = '\0';
	for (int i = 0; i < nrules && used < sizeof(buf); i++) {
		const struct rule *r = &rules[i];
		enum action shown = r->action == KILL && !r->file->enforce ? WARN : r->action;

		if (r->active)
			used += snprintf(buf + used, sizeof(buf) - used,
					 "rule=%s state=%s nodes=%s culprits=%s since=%ld\n",
					 r->name, action_name[shown], r->nodes,
					 shown == KILL ? r->culprits : "", (long)r->since);
	}
	if (!strcmp(buf, last))
		return;
	snprintf(last, sizeof(last), "%s", buf);

	f = fopen(STATE_FILE ".tmp", "w");
	if (!f)
		return;
	fputs(buf, f);
	fclose(f);
	rename(STATE_FILE ".tmp", STATE_FILE);
}

static void on_hup(int sig)
{
	reload = 1;
}

int main(int argc, char **argv)
{
	const char *dir = argc > 1 ? argv[1] : RULES_DIR;

	/* Must keep running while memory thrashes: never page ourselves out. */
	if (mlockall(MCL_CURRENT | MCL_FUTURE))
		perror("mlockall");
	mkdir("/run/numaguard", 0755);
	page_size = sysconf(_SC_PAGESIZE);
	clk_tck = sysconf(_SC_CLK_TCK);
	signal(SIGCHLD, SIG_IGN);		/* exec actions reap themselves */
	signal(SIGHUP, on_hup);
	find_kswapds();
	load_rules(dir);

	for (;;) {
		time_t now = time(NULL);

		if (reload) {
			reload = 0;
			if (skel)
				stop_tracing();
			load_rules(dir);
		}
		read_nodes();
		read_kswapds();
		read_host();

		if (!skel && tracing_wanted())
			start_tracing();
		for (int i = 0; i < nrules; i++)
			step(&rules[i], now);
		if (skel && !tracing_wanted())
			stop_tracing();

		write_state();
		sleep(1);
	}
}
