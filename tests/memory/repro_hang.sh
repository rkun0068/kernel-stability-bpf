#!/usr/bin/env bash
# Reproduce the NUMA-node hang and check that numaguard + a mock NodeManager
# end it. WILL stall the host: test hosts only.
#
#   1. Spark-like executors of random size (1-6G, random queue) fill the host
#      with anonymous memory, leaving ROOM_MB for page cache. Nothing is bound to
#      a node and there is no memory limit: where the pressure lands is up to the
#      kernel, as in production. An executor the kernel OOM-kills stays dead.
#   2. Shuffle writers keep the page cache dirty and readers keep re-reading a
#      3G file set that won't fit: reclaim scans hard but must wait for
#      writeback, and clean pages are read back (IO thrash).
#   3. numaguard judges with RULES (default: the shipped numa.rules), with scope
#      set to $ROOT/yarn and mode to enforce; the mock NM kills the first culprit
#      of every new kill verdict, at most 3 times.
#      GUARD=none skips this step: the baseline run to compare against.
#
# A probe in the root cgroup does a 4K O_DIRECT read every 5s, as any process on
# the host would when it misses the page cache; its latency is how hung the host is.
#
# Safety: every process runs under timeout -s KILL, so all memory is freed after
# MINUTES even if the host is too stalled to reach.
#
# Usage: sudo [READERS=300] [ROOM_MB=1500] [RULES=file] ./repro_hang.sh <numaguard binary|none> [minutes=15]
set -euo pipefail

GUARD=$1
MINUTES=${2:-15}
ROOT=/sys/fs/cgroup/ksb-repro
YARN=$ROOT/yarn				# executors only, like the NM's cgroup
WORK=/tmp/ksb-repro
FILES_GB=3
READERS=${READERS:-300}
WRITERS=8
ROOM_MB=${ROOM_MB:-1500}		# host memory left for page cache
PROBE_PID=
PROBE_LOG=/tmp/ksb-probe-$(basename "$GUARD").log
RULES=${RULES:-$(dirname "$0")/../../tools/memory/numaguard/rules.d/numa.rules}
QUEUES=(search-data-prod srda-prod szsc adhoc)

log() { echo "$(date +%T) $*"; }

cleanup() {
	log "cleaning up"
	[ "$GUARD" = none ] || pkill -f "$GUARD" || true
	kill $PROBE_PID 2>/dev/null || true
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

meminfo() { awk -v k="$1:" '$1 == k {print int($2 / 1024)}' /proc/meminfo; }
# "node0 free=..M file=..M dirty=..M node1 ..."
nodes() {
	for f in /sys/devices/system/node/node*/meminfo; do
		awk '$3 == "MemFree:" {f = $4} $3 == "FilePages:" {c = $4} $3 == "Dirty:" {d = $4}
			END {printf "node%s free=%dM file=%dM dirty=%dM ", $2, f / 1024, c / 1024, d / 1024}' "$f"
	done
}

mkdir -p "$WORK/files"
log "writing ${FILES_GB}G file set"
for i in $(seq $((FILES_GB * 4))); do
	dd if=/dev/urandom of="$WORK/files/f$i" bs=1M count=256 status=none
done
dd if=/dev/urandom of="$WORK/probe" bs=1M count=1024 status=none
sync; echo 1 > /proc/sys/vm/drop_caches

mkdir "$ROOT"
echo "+memory" > "$ROOT/cgroup.subtree_control"
mkdir "$YARN"
echo "+memory" > "$YARN/cgroup.subtree_control"

# 1. executors: everything reclaimable on the host except ROOM_MB
left=$(( $(meminfo MemFree) + $(meminfo Cached) - ROOM_MB ))
log "filling ${left}MB with random executors"
id=0
while [ $left -gt 0 ]; do
	id=$((id + 1)) mb=$(( (1 + RANDOM % 6) * 1024 ))
	[ $mb -le $left ] || mb=$left
	queue=${QUEUES[RANDOM % ${#QUEUES[@]}]}
	dir=$WORK/exec_$id
	mkdir -p "$dir/__spark_conf__"
	echo "spark.yarn.queue=$queue" > "$dir/__spark_conf__/__spark_conf__.properties"
	run_in "$YARN/exec_$id" "$dir" stress-ng --vm 1 --vm-bytes "${mb}M" --vm-hang 0 --oomable -q
	log "exec_$id ${mb}MB queue=$queue"
	left=$((left - mb))
	sleep $((RANDOM % 3))
done
sleep 60

# 2. shuffle writers (dirty pages) and readers (a working set that won't fit)
log "starting $WRITERS writers, $READERS readers"
mkdir -p "$WORK/shuffle"
run_in "$ROOT/writers" "$WORK" stress-ng --hdd "$WRITERS" --hdd-bytes 2G --temp-path "$WORK/shuffle" -q
for r in $(seq $READERS); do
	run_in "$ROOT/readers" "$WORK" sh -c "while :; do cat files/* > /dev/null; done"
done

# probe: "<epoch> <ms>" per read
: > "$PROBE_LOG"
while :; do
	t=$(date +%s%N)
	dd if="$WORK/probe" of=/dev/null bs=4k count=1 skip=$((RANDOM * 8)) iflag=direct status=none
	echo "$(date +%s) $((($(date +%s%N) - t) / 1000000))" >> "$PROBE_LOG"
	sleep 5
done &
PROBE_PID=$!

# 3. numaguard and the mock NodeManager
rm -f /run/numaguard/state /run/numaguard/events.log
mkdir -p "$WORK/rules"
sed -e "s|^scope.*|scope $YARN|" -e "s|^mode.*|mode enforce|" "$RULES" > "$WORK/rules/test.rules"
[ "$GUARD" = none ] || setsid "$GUARD" "$WORK/rules" < /dev/null > /tmp/ksb-guard.log 2>&1 &
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
		log "io $(grep full /proc/pressure/io | cut -d' ' -f2) D=$(grep -l '^State:.D' /proc/[0-9]*/status 2>/dev/null | wc -l) probe=$(tail -1 "$PROBE_LOG" | cut -d' ' -f2)ms $(nodes)${state%% culprits*}"
		next_log=$((SECONDS + 30))
	fi
done
log "done, kills=$kills"
awk '{n++; s += $2; if ($2 > max) max = $2; if ($2 >= 1000) slow++}
	END {printf "probe: %d reads, avg %dms, max %dms, %d >= 1s\n", n, s / n, max, slow}' "$PROBE_LOG"
