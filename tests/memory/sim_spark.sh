#!/usr/bin/env bash
# Simulate Spark executors on one NUMA node to drive that node into reclaim,
# like an over-committed NodeManager. For testing numawatch / numaguard.
#
# Each "executor" is a cgroup under /sys/fs/cgroup/ksb-sim running stress-ng
# with a random size, lifetime and YARN queue, started as old ones finish
# (batch jobs). Like a real container, it runs in a work dir holding
# __spark_conf__/__spark_conf__.properties with spark.yarn.queue.
# Safety: everything is confined to one node and capped at 95% of it, the run
# stops after MINUTES, and aborts early if host memory PSI full gets too high.
#
# Usage: sudo ./sim_spark.sh [node=1] [minutes=20] [cpus=node|all]
#   cpus=all lets executors run on every CPU (like unpinned YARN containers),
#   so the whole host stalls on the node, not just that node's CPUs.
set -euo pipefail

NODE=${1:-1}
MINUTES=${2:-20}
CPUS=${3:-node}
ROOT=/sys/fs/cgroup/ksb-sim
ABORT_PSI=60				# host memory PSI full avg10
OVERCOMMIT=110				# executors requested, % of node memory
WORK=/tmp/ksb-sim-work
QUEUES=(search-data-prod srda-prod szsc adhoc)

NODE_MB=$(awk '/MemTotal/ {print int($4 / 1024)}' /sys/devices/system/node/node$NODE/meminfo)
declare -A SIZE_MB			# executor id -> requested MB

log() { echo "$(date +%T) $*"; }

# cgroupfs files always report size 0, so test the content, not [ -s ]
empty() { ! grep -q . "$1/cgroup.procs"; }

cleanup() {
	log "cleaning up"
	for cg in "$ROOT"/exec_* "$ROOT"/shuffle; do
		[ -d "$cg" ] || continue
		xargs -r kill -9 < "$cg/cgroup.procs" 2>/dev/null || true
		while ! empty "$cg"; do sleep 0.2; done
		rmdir "$cg"
	done
	rmdir "$ROOT" 2>/dev/null || true
	rm -rf /tmp/ksb-sim-shuffle "$WORK"
}
trap cleanup EXIT

# run "$@" inside cgroup $1, in the background
run_in() {
	local cg=$1; shift
	mkdir -p "$cg"
	( echo $BASHPID > "$cg/cgroup.procs"; exec "$@" ) &
}

start_executor() {
	local id=$1 gb=$((RANDOM % 7 + 2)) secs=$((RANDOM % 240 + 60))
	local queue=${QUEUES[RANDOM % ${#QUEUES[@]}]} dir=$WORK/exec_$id
	SIZE_MB[$id]=$((gb * 1024))
	mkdir -p "$dir/__spark_conf__"
	echo "spark.yarn.queue=$queue" > "$dir/__spark_conf__/__spark_conf__.properties"
	(cd "$dir" && run_in "$ROOT/exec_$id" timeout "$secs" stress-ng --vm 1 --vm-bytes "${gb}G" --vm-keep -q)
	log "start exec_$id ${gb}G for ${secs}s queue=$queue"
}

reap_finished() {
	for id in "${!SIZE_MB[@]}"; do
		local cg=$ROOT/exec_$id
		if empty "$cg"; then
			grep -q oom_kill' [1-9]' "$cg/memory.events" && log "exec_$id was OOM-killed"
			rmdir "$cg"
			unset "SIZE_MB[$id]"
		fi
	done
}

requested_mb() {
	local sum=0
	for mb in "${SIZE_MB[@]}"; do sum=$((sum + mb)); done
	echo $sum
}

# all executors share one parent pinned to the node and capped at 95% of it
mkdir "$ROOT"
echo "+cpuset +memory" > "$ROOT/cgroup.subtree_control"
if [ "$CPUS" = all ]; then
	cat /sys/devices/system/cpu/online > "$ROOT/cpuset.cpus"
else
	cat /sys/devices/system/node/node$NODE/cpulist > "$ROOT/cpuset.cpus"
fi
echo "$NODE" > "$ROOT/cpuset.mems"
echo $((NODE_MB * 95 / 100))M > "$ROOT/memory.max"
log "node$NODE: ${NODE_MB}MB, cap $((NODE_MB * 95 / 100))MB, run ${MINUTES} min"

# shuffle writers: page cache and disk IO on the same node
mkdir -p /tmp/ksb-sim-shuffle
run_in "$ROOT/shuffle" stress-ng --hdd 2 --hdd-bytes 2G --temp-path /tmp/ksb-sim-shuffle -q

next_id=1
end=$((SECONDS + MINUTES * 60))
while [ $SECONDS -lt $end ]; do
	psi=$(awk -F'[ =]' '/^full/ {print int($3)}' /proc/pressure/memory)
	if [ "$psi" -ge $ABORT_PSI ]; then
		log "abort: host memory PSI full avg10=$psi"
		exit 1
	fi
	reap_finished
	while [ "$(requested_mb)" -lt $((NODE_MB * OVERCOMMIT / 100)) ]; do
		start_executor $next_id
		next_id=$((next_id + 1))
	done
	sleep 5
done
log "done"
