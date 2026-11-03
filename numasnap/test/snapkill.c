// SPDX-License-Identifier: GPL-2.0
/*
 * snapkill: stands in for the scheduler (YARN, Kubernetes, ...) that acts on
 * numasnap. While DIR/snapshot keeps being refreshed, kill the first container
 * in it (most anonymous memory on the starved node), skipping names that end
 * with --exclude, then wait until its cgroup is empty or 10s, and for a
 * snapshot taken after that, before the next.
 * Only while the snapshot says state=trigger: recovering and healthy mean stop.
 *
 * Like numasnap it runs in an IO hang: mlockall(), procfs/sysfs/tmpfs only,
 * pidfd to signal, no allocation in the loop.
 *
 * usage: snapkill --scope DIR [--dir DIR] [--exclude SUFFIX] [--min GB] [--max-kills N]
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static char snap[1 << 17];

static int slurp(const char *path, char *buf, int size)
{
	int fd = open(path, O_RDONLY), n;

	n = fd < 0 ? 0 : read(fd, buf, size - 1);
	if (fd >= 0)
		close(fd);
	buf[n > 0 ? n : 0] = 0;
	return n;
}

static unsigned long long field(const char *line, const char *key)
{
	const char *p = strstr(line, key);

	return p ? strtoull(p + strlen(key), NULL, 10) : 0;
}

/* state=trigger, whatever field follows it */
static int is_trigger(const char *snap)
{
	const char *p = strstr(snap, " state=");

	return p && !strncmp(p + 7, "trigger", 7) && (p[14] == ' ' || p[14] == '\n');
}

static int kill_cgroup(const char *cg)
{
	char path[512], pids[1 << 14], *p, *e;
	int n, killed = 0;

	snprintf(path, sizeof(path), "%s/cgroup.procs", cg);
	slurp(path, pids, sizeof(pids));
	for (p = pids; (n = strtol(p, &e, 10)) > 0; p = e) {
		/* pidfd: a pid read from cgroup.procs may be reused before we signal it */
		int pfd = syscall(SYS_pidfd_open, n, 0);

		if (pfd >= 0 && !syscall(SYS_pidfd_send_signal, pfd, SIGKILL, NULL, 0))
			killed++;
		if (pfd >= 0)
			close(pfd);
	}
	return killed;
}

static int populated(const char *cg)
{
	char path[512], b[128];

	snprintf(path, sizeof(path), "%s/cgroup.events", cg);
	slurp(path, b, sizeof(b));
	return strstr(b, "populated 1") != NULL;
}

int main(int argc, char **argv)
{
	static const struct option opts[] = {
		{ "scope", 1, 0, 's' }, { "dir", 1, 0, 'd' }, { "exclude", 1, 0, 'x' },
		{ "min", 1, 0, 'm' }, { "max-kills", 1, 0, 'k' }, { 0 }
	};
	const char *scope = NULL, *dir = "/run/numasnap", *exclude = "_000001";
	unsigned long long min = 1ULL << 30;
	int c, kills = 0, max_kills = 10;
	char path[512], victim[512] = "";
	time_t kill_at = 0, gone_at = 0;

	while ((c = getopt_long(argc, argv, "", opts, NULL)) != -1) {
		switch (c) {
		case 's': scope = optarg; break;
		case 'd': dir = optarg; break;
		case 'x': exclude = optarg; break;
		case 'm': min = strtoull(optarg, NULL, 10) << 30; break;
		case 'k': max_kills = atoi(optarg); break;
		default: scope = NULL; optind = argc; break;
		}
	}
	if (!scope) {
		fprintf(stderr, "usage: %s --scope DIR [--dir DIR] [--exclude SUFFIX] [--min GB] [--max-kills N]\n",
			argv[0]);
		return 2;
	}
	snprintf(path, sizeof(path), "%s/snapshot", dir);
	if (mlockall(MCL_CURRENT | MCL_FUTURE))
		perror("mlockall");
	if (setpriority(PRIO_PROCESS, 0, -20))	/* ahead of the tasks stuck in reclaim */
		perror("setpriority");
	setvbuf(stdout, NULL, _IOLBF, 0);

	for (;; sleep(1)) {
		char key[16], *line, *next;
		int target;
		time_t now = time(NULL);

		if (victim[0]) {		/* wait for the last one to go */
			if (populated(victim) && now - kill_at <= 10)
				continue;
			printf("%ld %s %s after %lds\n", (long)now, victim,
			       populated(victim) ? "still running" : "gone", (long)(now - kill_at));
			victim[0] = 0, gone_at = now;
		}
		/* numasnap refreshes the snapshot every second while the host stalls */
		if (!slurp(path, snap, sizeof(snap)) || now - (time_t)field(snap, "ts=") > 3 || kills >= max_kills)
			continue;
		/* written in place: a read that crossed a write has seq= and end= apart */
		if (field(snap, " seq=") != field(snap, "\nend="))
			continue;
		/* state= was decided at mts=, before sampling: one decided before the
		 * last victim went still says trigger */
		if ((time_t)field(snap, " mts=") <= gone_at)
			continue;
		target = field(snap, "target=");
		snprintf(key, sizeof(key), "\nnode=%d ", target);
		line = strstr(snap, key);
		/* the snapshot keeps coming until the host is healthy: act only on trigger */
		if (!line || !is_trigger(snap))
			continue;
		snprintf(key, sizeof(key), " anon%d=", target);
		for (line = snap; line; line = next) {
			char name[256];
			int len;

			next = strchr(line, '\n');
			if (next)
				*next++ = 0;
			if (strncmp(line, "name=", 5) || sscanf(line + 5, "%255s", name) != 1)
				continue;
			len = strlen(name);
			if (len >= (int)strlen(exclude) && !strcmp(name + len - strlen(exclude), exclude))
				continue;
			if (field(line, key) < min)	/* sorted: nobody after this holds more */
				break;
			snprintf(victim, sizeof(victim), "%s/%s", scope, name);
			if (!populated(victim)) {	/* killed already, its memory not freed yet */
				victim[0] = 0;
				continue;
			}
			printf("%ld kill %s anon%d=%.1fG: %d procs\n", (long)now, name, target,
			       field(line, key) / 1073741824.0, kill_cgroup(victim));
			kill_at = now, kills++;
			break;
		}
	}
}
