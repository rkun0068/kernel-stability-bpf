// SPDX-License-Identifier: GPL-2.0
/*
 * numasnap: when one NUMA node fills up and the host hangs on IO, record how
 * much anonymous memory every container holds on every node, so whoever kills
 * containers can pick the ones holding that node. It only collects.
 *
 * The hang builds up in three stages, checked every second:
 *
 *   1 node full   anonymous pages are >= --anon percent of a node's memory:
 *                 without swap, reclaim cannot take them back
 *   2 no reclaim  reclaim frees <= --eff percent of what it scans; what it
 *                 does free is read back from disk
 *   3 stall       tasks stop making progress: IO PSI full avg10 >= --io
 *                 (the reads saturate the disk) or memory PSI full avg10
 *                 >= --mem (they are stuck in reclaim before reading)
 *
 * Once stage 3 holds for --hold seconds it samples every node's page frames and
 * writes every second until the host is healthy, with state= in the snapshot:
 *
 *   trigger      stage 3 holds: act on the snapshot
 *   recovering   stage 3 is gone but the host is not healthy yet: wait
 *   healthy      held for 30s, the last snapshot: all of
 *                  the node: anon < 85%, or free + file > high watermark + 5G
 *                  reclaim frees > 70% of what it scans (vmpressure "low" is > 67%),
 *                  or barely scans
 *                  IO and memory PSI full avg10 < 40
 *
 * Recovery needs more than the trigger thresholds undone: in a hang the
 * efficiency swings around 10% while IO stays saturated.
 *
 *   DIR/snapshot   host metrics, per-node memory, then the containers under
 *                  --scope sorted by anonymous memory on the full node
 *   DIR/events     stage changes (held 5s), trigger, snapshot (top 3),
 *                  recovering, healthy,
 *                  plus SIGKILLs seen by eBPF
 *
 * It must keep running while the system disk is saturated: after setup it
 * only touches procfs, sysfs, BPF maps and DIR (put it on tmpfs), and holds
 * its memory with mlockall().
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdio.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <linux/types.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "numasnap.h"

#define VERSION		1
#define GiB		(1ULL << 30)
#define KPF_ANON	(1ULL << 12)
#define KPF_THP_TAIL	(1ULL << 16)
#define MAX_CONT	1024
#define MAX_ZONES	4

static struct {
	const char *scope, *dir, *bpf;
	double io, mem, eff, anon;
	int hold, samples;
} cfg = {
	.scope = "/sys/fs/cgroup", .dir = "/run/numasnap", .bpf = "numasnap.bpf.o",
	.io = 80,			/* IO PSI full avg10; 6 hangs peak 96-98, other days <= 77 */
	.mem = 80,			/* memory PSI full avg10; 6 hangs peak 88-98, other days <= 73 */
	.eff = 10,			/* sar -B in hangs: 2-9%, normally above 90% */
	.anon = 90,			/* 6 hangs: reached 1-3h before, peak 95-97% */
	.hold = 30, .samples = 100000,
};

static char buf[1 << 16], out[1 << 17];
static int olen;

static void put(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	olen += vsnprintf(out + olen, sizeof(out) - olen, fmt, ap);
	va_end(ap);
	if (olen >= (int)sizeof(out))
		olen = sizeof(out) - 1;
}

/* write out[] to dir/name: whole file replaced at once, readers never see half */
static void publish(const char *name)
{
	char tmp[256], dst[256];
	int fd;

	snprintf(tmp, sizeof(tmp), "%s/.%s", cfg.dir, name);
	snprintf(dst, sizeof(dst), "%s/%s", cfg.dir, name);
	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd >= 0 && write(fd, out, olen) == olen)
		rename(tmp, dst);
	if (fd >= 0)
		close(fd);
	olen = 0;
}

/* events: appended, restarted at 1M; tmpfs, so it cannot block */
static void event(const char *fmt, ...)
{
	static int fd = -1;
	char line[512];
	va_list ap;
	int n;

	if (fd < 0) {
		snprintf(line, sizeof(line), "%s/events", cfg.dir);
		fd = open(line, O_WRONLY | O_CREAT | O_APPEND, 0644);
	}
	n = snprintf(line, sizeof(line), "ts=%ld ", (long)time(NULL));
	va_start(ap, fmt);
	n += vsnprintf(line + n, sizeof(line) - n - 1, fmt, ap);
	va_end(ap);
	line[n++] = '\n';
	if (lseek(fd, 0, SEEK_END) > (1 << 20))
		ftruncate(fd, 0);
	if (write(fd, line, n) < 0) {
		/* nothing to do */
	}
}

/* ---- metrics ---- */

static int nodes;
static __u64 high[NS_MAX_NODES];				/* watermark, bytes */
static struct { __u64 start, span; } zone[NS_MAX_NODES][MAX_ZONES];
static int nzone[NS_MAX_NODES];
static int fd_psi, fd_mem, fd_stat, fd_vmstat, fd_flags, fd_cg, fd_meminfo[NS_MAX_NODES];

struct metrics {
	double io, mem;
	__u64 cpu, iowait, scan, steal, refault, majflt;
	__u64 total[NS_MAX_NODES], free[NS_MAX_NODES], file[NS_MAX_NODES], anon[NS_MAX_NODES];
};

static const char *slurp(int fd)
{
	ssize_t n = pread(fd, buf + 1, sizeof(buf) - 2, 0);

	buf[0] = '\n';				/* so "\nkey " matches the first line */
	buf[1 + (n > 0 ? n : 0)] = 0;
	return buf;
}

static __u64 get(const char *s, const char *key)
{
	const char *p = strstr(s, key);

	return p ? strtoull(p + strlen(key), NULL, 10) : 0;
}

static void read_metrics(struct metrics *m)
{
	const char *b;
	__u64 v[8] = { 0 };

	b = strstr(slurp(fd_psi), "full avg10=");
	m->io = b ? atof(b + 11) : 0;
	b = strstr(slurp(fd_mem), "full avg10=");
	m->mem = b ? atof(b + 11) : 0;

	sscanf(slurp(fd_stat) + 1, "cpu %llu %llu %llu %llu %llu %llu %llu %llu",
	       &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6], &v[7]);
	m->cpu = v[0] + v[1] + v[2] + v[3] + v[4] + v[5] + v[6] + v[7];
	m->iowait = v[4];

	b = slurp(fd_vmstat);
	m->scan = get(b, "\npgscan_kswapd ") + get(b, "\npgscan_direct ");
	m->steal = get(b, "\npgsteal_kswapd ") + get(b, "\npgsteal_direct ");
	m->refault = get(b, "\nworkingset_refault ");
	m->majflt = get(b, "\npgmajfault ");

	for (int n = 0; n < nodes; n++) {
		b = slurp(fd_meminfo[n]);
		m->total[n] = get(b, "MemTotal:") << 10;
		m->free[n] = get(b, "MemFree:") << 10;
		m->file[n] = get(b, "FilePages:") << 10;
		m->anon[n] = get(b, "AnonPages:") << 10;
	}
}

/* ---- containers: sample each node's pfns, count anonymous pages per cgroup ---- */

static struct container {
	char name[96];
	__u64 cgid;
	__u64 anon[NS_MAX_NODES];	/* bytes, estimated */
} cont[MAX_CONT];
static int ncont;

static void list_containers(void)
{
	char dirent_buf[1 << 15], path[512];
	int fd = open(cfg.scope, O_RDONLY | O_DIRECTORY), n, off;
	struct stat st;

	ncont = 0;
	/* getdents64 into a stack buffer: opendir() would malloc */
	while (fd >= 0 && (n = syscall(SYS_getdents64, fd, dirent_buf, sizeof(dirent_buf))) > 0) {
		for (off = 0; off < n;) {
			struct { __u64 ino; __s64 off; unsigned short len; unsigned char type; char name[]; }
				*d = (void *)(dirent_buf + off);

			off += d->len;
			if (d->type != 4 /* DT_DIR */ || d->name[0] == '.' || ncont == MAX_CONT)
				continue;
			snprintf(path, sizeof(path), "%s/%s", cfg.scope, d->name);
			if (stat(path, &st))
				continue;
			snprintf(cont[ncont].name, sizeof(cont[ncont].name), "%s", d->name);
			cont[ncont++].cgid = st.st_ino;	/* cgroup v2: inode number == cgroup id */
		}
	}
	if (fd >= 0)
		close(fd);
}

static void sample(void)
{
	static __u64 x = 88172645463325252ULL;
	__u64 span, r, pfn, flags, cg;
	int n, i, z, c;

	for (c = 0; c < ncont; c++)
		memset(cont[c].anon, 0, sizeof(cont[c].anon));
	for (n = 0; n < nodes; n++) {
		for (span = 0, z = 0; z < nzone[n]; z++)
			span += zone[n][z].span;
		for (i = 0; i < cfg.samples; i++) {
			x ^= x << 13, x ^= x >> 7, x ^= x << 17;
			for (r = x % span, z = 0; r >= zone[n][z].span; z++)
				r -= zone[n][z].span;
			pfn = zone[n][z].start + r;
			if (pread(fd_flags, &flags, 8, pfn * 8) != 8 || !(flags & KPF_ANON))
				continue;
			if (flags & KPF_THP_TAIL)	/* 5.4 records the memcg on the head page only */
				pfn &= ~511ULL;
			if (pread(fd_cg, &cg, 8, pfn * 8) != 8)
				continue;
			for (c = 0; c < ncont && cont[c].cgid != cg; c++)
				;
			if (c < ncont)
				cont[c].anon[n] += span * 4096 / cfg.samples;
		}
	}
}

/* ---- eBPF ---- */

static int map_kswapd = -1, map_refault = -1, map_kills = -1, map_seq = -1;

static void bpf_setup(void)
{
	struct bpf_object *obj = bpf_object__open_file(cfg.bpf, NULL);
	struct bpf_program *p;

	if (libbpf_get_error(obj) || bpf_object__load(obj)) {
		fprintf(stderr, "eBPF %s not loaded, continuing without it\n", cfg.bpf);
		return;
	}
	bpf_object__for_each_program(p, obj)
		if (libbpf_get_error(bpf_program__attach(p)))
			fprintf(stderr, "eBPF: cannot attach %s\n", bpf_program__name(p));
	map_kswapd = bpf_object__find_map_fd_by_name(obj, "kswapd_stat");
	map_refault = bpf_object__find_map_fd_by_name(obj, "refault");
	map_kills = bpf_object__find_map_fd_by_name(obj, "kills");
	map_seq = bpf_object__find_map_fd_by_name(obj, "kill_seq");
}

static const char *kswapd(int n)
{
	struct ns_kswapd k = { 0 };
	__u32 key = n;

	if (map_kswapd < 0)
		return "unknown";
	bpf_map_lookup_elem(map_kswapd, &key, &k);
	return k.last_wake_ns > k.last_sleep_ns ? "running" : "asleep";
}

static __u64 refaults(__u64 cgid)
{
	__u64 v = 0;

	if (map_refault >= 0)
		bpf_map_lookup_elem(map_refault, &cgid, &v);
	return v;
}

static void kill_events(void)
{
	static __u64 seen;
	__u64 seq = 0;
	__u32 i = 0;

	if (map_seq < 0)
		return;
	bpf_map_lookup_elem(map_seq, &i, &seq);
	for (; seen < seq; seen++) {
		struct ns_kill k;

		i = seen % NS_KILL_RING;
		if (!bpf_map_lookup_elem(map_kills, &i, &k))
			event("sigkill sender=%s/%u target=%s/%u", k.sender_comm, k.sender_pid,
			      k.target_comm, k.target_pid);
	}
}

/* ---- setup ---- */

static void setup(void)
{
	FILE *f = fopen("/proc/zoneinfo", "r");
	char line[256];
	int n = -1, z = -1;
	unsigned long long v;

	while (f && fgets(line, sizeof(line), f)) {
		if (sscanf(line, "Node %d, zone", &n) == 1 && n < NS_MAX_NODES) {
			nodes = n + 1 > nodes ? n + 1 : nodes;
			z = nzone[n] < MAX_ZONES ? nzone[n]++ : -1;
		} else if (sscanf(line, " high %llu", &v) == 1 && n >= 0) {
			high[n] += v * 4096;
		} else if (sscanf(line, " spanned %llu", &v) == 1 && z >= 0) {
			zone[n][z].span = v;
		} else if (sscanf(line, " start_pfn: %llu", &v) == 1 && z >= 0) {
			zone[n][z].start = v;
		}
	}
	if (f)
		fclose(f);
	fd_psi = open("/proc/pressure/io", O_RDONLY);
	fd_mem = open("/proc/pressure/memory", O_RDONLY);
	fd_stat = open("/proc/stat", O_RDONLY);
	fd_vmstat = open("/proc/vmstat", O_RDONLY);
	fd_flags = open("/proc/kpageflags", O_RDONLY);
	fd_cg = open("/proc/kpagecgroup", O_RDONLY);
	for (n = 0; n < nodes; n++) {
		snprintf(line, sizeof(line), "/sys/devices/system/node/node%d/meminfo", n);
		fd_meminfo[n] = open(line, O_RDONLY);
	}
	mkdir(cfg.dir, 0755);
	if (!nodes || fd_psi < 0 || fd_mem < 0 || fd_flags < 0 || fd_cg < 0) {
		fprintf(stderr, "needs root, PSI and /proc/kpagecgroup\n");
		exit(1);
	}
}

static int target;
static const char *state;

static int by_target_anon(const void *a, const void *b)
{
	__u64 x = ((const struct container *)a)->anon[target], y = ((const struct container *)b)->anon[target];

	return x < y ? 1 : x > y ? -1 : 0;
}

static void snapshot(const struct metrics *m, const struct metrics *prev)
{
	int c, n;
	time_t now;

	list_containers();
	sample();
	qsort(cont, ncont, sizeof(cont[0]), by_target_anon);
	now = time(NULL);	/* sampling can take seconds in a stall: stamp when done */

	put("version=%d ts=%ld io_full=%.1f mem_full=%.1f iowait=%.1f scan=%llu steal=%llu refault=%llu majflt=%llu target=%d state=%s\n",
	    VERSION, (long)now, m->io, m->mem,
	    m->cpu > prev->cpu ? 100.0 * (m->iowait - prev->iowait) / (m->cpu - prev->cpu) : 0,
	    m->scan - prev->scan, m->steal - prev->steal, m->refault - prev->refault,
	    m->majflt - prev->majflt, target, state);
	for (n = 0; n < nodes; n++)
		put("node=%d total=%llu free=%llu file=%llu anon=%llu high=%llu kswapd=%s\n",
		    n, m->total[n], m->free[n], m->file[n], m->anon[n], high[n], kswapd(n));
	for (c = 0; c < ncont; c++) {
		put("name=%s cgid=%llu refault=%llu", cont[c].name, cont[c].cgid, refaults(cont[c].cgid));
		for (n = 0; n < nodes; n++)
			put(" anon%d=%llu", n, cont[c].anon[n]);
		put("\n");
	}
	publish("snapshot");
	event("snapshot target=%d top=%s:%llu,%s:%llu,%s:%llu", target,
	      ncont > 0 ? cont[0].name : "-", ncont > 0 ? cont[0].anon[target] : 0,
	      ncont > 1 ? cont[1].name : "-", ncont > 1 ? cont[1].anon[target] : 0,
	      ncont > 2 ? cont[2].name : "-", ncont > 2 ? cont[2].anon[target] : 0);
}

/* stage of the hang (see top); *full is set to the node that is full */
static int stage(const struct metrics *m, const struct metrics *prev, int *full)
{
	__u64 scan;
	int n;

	for (*full = -1, n = 0; n < nodes; n++)
		if (100.0 * m->anon[n] >= cfg.anon * m->total[n] &&
		    (*full < 0 || m->free[n] + m->file[n] < m->free[*full] + m->file[*full]))
			*full = n;
	if (*full < 0)
		return 0;
	scan = m->scan - prev->scan;
	if (!scan || 100.0 * (m->steal - prev->steal) / scan > cfg.eff)
		return 1;
	return m->io >= cfg.io || m->mem >= cfg.mem ? 3 : 2;
}

static int healthy(const struct metrics *m, const struct metrics *prev)
{
	__u64 scan = m->scan - prev->scan;

	return (100 * m->anon[target] < 85 * m->total[target] ||
		m->free[target] + m->file[target] > high[target] + (5ULL << 30)) &&
	       (scan < 1000 || 100.0 * (m->steal - prev->steal) / scan > 70) &&
	       m->io < 40 && m->mem < 40;
}

int main(int argc, char **argv)
{
	static const struct option opts[] = {
		{ "scope", 1, 0, 's' }, { "dir", 1, 0, 'd' }, { "bpf", 1, 0, 'b' },
		{ "io", 1, 0, 'i' }, { "mem", 1, 0, 'M' }, { "eff", 1, 0, 'e' }, { "anon", 1, 0, 'a' },
		{ "hold", 1, 0, 'h' }, { "samples", 1, 0, 'n' }, { 0 }
	};
	struct metrics prev, m;
	int c, full, st, shown = 0, cand = 0, cand_n = 0, held = 0, well = 0, active = 0;

	while ((c = getopt_long(argc, argv, "", opts, NULL)) != -1) {
		switch (c) {
		case 's': cfg.scope = optarg; break;
		case 'd': cfg.dir = optarg; break;
		case 'b': cfg.bpf = optarg; break;
		case 'i': cfg.io = atof(optarg); break;
		case 'M': cfg.mem = atof(optarg); break;
		case 'e': cfg.eff = atof(optarg); break;
		case 'a': cfg.anon = atof(optarg); break;
		case 'h': cfg.hold = atoi(optarg); break;
		case 'n': cfg.samples = atoi(optarg); break;
		default:
			fprintf(stderr, "usage: %s [--scope DIR] [--dir DIR] [--bpf FILE]\n"
				"  [--io N] [--mem N] [--eff PCT] [--anon PCT] [--hold SEC] [--samples N]\n", argv[0]);
			return 2;
		}
	}

	/* everything that may read the disk happens before mlockall() */
	setup();
	bpf_setup();
	if (mlockall(MCL_CURRENT | MCL_FUTURE))
		perror("mlockall");
	/* ahead of the tasks that hog the CPUs in reclaim; it sleeps most of the time */
	/* realtime is refused inside a cgroup without an RT budget: then nice -20 */
	if (sched_setscheduler(0, SCHED_RR, &(struct sched_param){ .sched_priority = 1 }) &&
	    setpriority(PRIO_PROCESS, 0, -20))
		perror("setpriority");
	event("start version=%d nodes=%d scope=%s io=%.0f mem=%.0f eff=%.0f anon=%.0f hold=%d",
	      VERSION, nodes, cfg.scope, cfg.io, cfg.mem, cfg.eff, cfg.anon, cfg.hold);

	read_metrics(&prev);
	for (;; prev = m) {
		sleep(1);
		read_metrics(&m);
		st = stage(&m, &prev, &full);

		/* log a stage once it has lasted 5s, so a flickering metric stays quiet */
		cand_n = st == cand ? cand_n + 1 : 1, cand = st;
		if (cand_n == 5 && st != shown)
			event("stage=%d node=%d free=%llu file=%llu scan=%llu steal=%llu refault=%llu io_full=%.1f mem_full=%.1f",
			      st, full, full < 0 ? 0 : m.free[full], full < 0 ? 0 : m.file[full],
			      m.scan - prev.scan, m.steal - prev.steal, m.refault - prev.refault, m.io, m.mem), shown = st;

		held = st == 3 ? held + 1 : 0;
		if (!active && held >= cfg.hold) {
			/* kept until healthy, so freeing it does not move the ranking elsewhere */
			target = full;
			event("trigger node=%d io_full=%.1f mem_full=%.1f refault=%llu", target, m.io, m.mem, m.refault - prev.refault);
			active = 1, state = "trigger";
		} else if (active) {
			if (st == 3 && strcmp(state, "trigger"))
				event("trigger again io_full=%.1f mem_full=%.1f", m.io, m.mem), state = "trigger";
			else if (st != 3 && !strcmp(state, "trigger"))
				event("recovering io_full=%.1f mem_full=%.1f", m.io, m.mem), state = "recovering";
			well = st != 3 && healthy(&m, &prev) ? well + 1 : 0;
			if (well >= 30)
				event("healthy io_full=%.1f mem_full=%.1f", m.io, m.mem), state = "healthy", active = 0;
		}
		if (active || well >= 30)
			snapshot(&m, &prev);
		if (!active)
			well = 0;
		kill_events();
	}
}
