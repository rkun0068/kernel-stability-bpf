#!/usr/bin/env bash
# Reproduce the NUMA-node hang and check that numaguard + a mock NodeManager
# end it. WILL stall the host: test hosts only.
#
#   1. Spark-like executors fill node NODE with anonymous memory (allocate, then
#      idle), leaving ~1.5G of the node for page cache. No memory limit.
#   2. Shuffle writers keep the node's page cache dirty and readers keep
#      re-reading a 3G file set it can't hold: reclaim scans hard but must wait
#      for writeback, and clean pages are read back (IO thrash). The kernel
#      keeps making progress, so it never OOMs.
#   3. numaguard --enforce (built with CGROUP_ROOT=$ROOT/yarn) judges; the mock NM
#      kills the first culprit on every new kill verdict, at most 3 times.
#
# Safety: every process runs under timeout -s KILL, so all memory is freed after
# MINUTES even if the host is too stalled to reach.
#
# Usage: sudo ./repro_hang.sh <numaguard binary> [node=1] [minutes=15]
set -euo pipefail

GUARD=$1
NODE=${2:-1}
MINUTES=${3:-15}
ROOT=/sys/fs/cgroup/ksb-repro
YARN=$ROOT/yarn				# executors only, like the NM's cgroup
WORK=/tmp/ksb-repro
FILES_GB=3
READERS=48
WRITERS=8
EXECUTORS=8
QUEUES=(search-data-prod srda-prod szsc adhoc)

log() { echo "$(date +%T) $*"; }

cleanup() {
	log "cleaning up"
	pkill -f "$GUARD" || true
	for procs in $(find "$ROOT" -name cgroup.procs 2>/dev/null); do
		xargs -r kill -9 < "$procs" 2>/dev/null || true
	done
	for cg in $(find "$ROOT" -depth -type d 2>/dev/null); do
		while grep -q . "$cg/cgroup.procs"; do sleep 0.2; done
		rmdir "$cg"
	done
	rm -rf "$WORK"
}
trap cleanup EXIT

# run "$@" in cgroup $1 from directory $2, killed after MINUTES whatever happens
run_in() {
	local cg=$1 dir=$2; shift 2
	mkdir -p "$cg"
	( cd "$dir"; echo $BASHPID > "$cg/cgroup.procs"; exec timeout -s KILL "${MINUTES}m" "$@" ) &
}

meminfo() { awk -v k="$1:" '$3 == k {print int($4 / 1024)}' /sys/devices/system/node/node$NODE/meminfo; }

mkdir -p "$WORK/files"
log "writing ${FILES_GB}G file set"
for i in $(seq $((FILES_GB * 4))); do
	dd if=/dev/urandom of="$WORK/files/f$i" bs=1M count=256 status=none
done
sync; echo 1 > /proc/sys/vm/drop_caches

mkdir "$ROOT"
echo "+cpuset +memory" > "$ROOT/cgroup.subtree_control"
cat /sys/devices/system/cpu/online > "$ROOT/cpuset.cpus"
echo "$NODE" > "$ROOT/cpuset.mems"
mkdir "$YARN"
echo "+cpuset +memory" > "$YARN/cgroup.subtree_control"

# 1. executors: everything reclaimable on the node except 1.5G
fill_mb=$(( $(meminfo MemFree) + $(meminfo FilePages) - 1500 ))
log "node$NODE: filling ${fill_mb}MB with $EXECUTORS executors"
for id in $(seq $EXECUTORS); do
	queue=${QUEUES[RANDOM % ${#QUEUES[@]}]}
	dir=$WORK/exec_$id
	mkdir -p "$dir/__spark_conf__"
	echo "spark.yarn.queue=$queue" > "$dir/__spark_conf__/__spark_conf__.properties"
	run_in "$YARN/exec_$id" "$dir" stress-ng --vm 1 --vm-bytes "$((fill_mb / EXECUTORS))M" --vm-hang 0 -q
	log "exec_$id $((fill_mb / EXECUTORS))MB queue=$queue"
done
sleep 60

# 2. shuffle writers (dirty pages) and readers (a working set that won't fit)
log "starting $WRITERS writers, $READERS readers"
mkdir -p "$WORK/shuffle"
run_in "$ROOT/writers" "$WORK" stress-ng --hdd "$WRITERS" --hdd-bytes 2G --temp-path "$WORK/shuffle" -q
for r in $(seq $READERS); do
	run_in "$ROOT/readers" "$WORK" sh -c "while :; do cat files/* > /dev/null; done"
done

# 3. numaguard and the mock NodeManager
rm -f /run/numaguard/state /run/numaguard/events.log
setsid "$GUARD" --enforce < /dev/null > /dev/null 2>&1 &
kills=0 last= next_log=0
end=$((SECONDS + MINUTES * 60))
while [ $SECONDS -lt $end ]; do
	sleep 2
	state=$(cat /run/numaguard/state 2>/dev/null || true)
	victim=$(sed -n 's/.*state=kill .*culprits=\([^(,]*\).*/\1/p' <<< "$state")
	if [ -n "$victim" ] && [ "$victim" != "$last" ] && [ $kills -lt 3 ] && [ -d "$YARN/$victim" ]; then
		log "NM: kill $victim ($state)"
		xargs -r kill -9 < "$YARN/$victim/cgroup.procs"
		last=$victim kills=$((kills + 1))
	fi
	if [ $SECONDS -ge $next_log ]; then
		log "io $(grep full /proc/pressure/io | cut -d' ' -f2) node$NODE free=$(meminfo MemFree)M file=$(meminfo FilePages)M dirty=$(meminfo Dirty)M ${state%% nodes*}"
		next_log=$((SECONDS + 30))
	fi
done
log "done, kills=$kills"
