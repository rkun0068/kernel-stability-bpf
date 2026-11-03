#!/bin/bash
# Reproduce the Spark hang on a 2-node test host, inside /sys/fs/cgroup/os_test:
#   node1 is full of anonymous memory (executors), node0 still holds page cache
#   nobody reclaims; the code pages left on node1 are hot, so kswapd1 scans a
#   lot and frees little (low efficiency), and what it frees is read back from
#   a slow disk: IO PSI full and iowait climb until the host hangs.
#
#   node1  c_big 12G + fill, c_split 5G, app_000001 4G   anonymous, no swap
#          c_io: hot.c, executable mapping of HOT_MB      page cache, refaulting
#   node0  c_node0 10G, c_split 4G                       anonymous
#   sizes are for a 32G node; SCALE multiplies them (8 for a 256G node)
#          f4..f7 read once                              page cache, left alone
#   c_churn runs on node1 CPUs with no memory binding: like executors, it keeps
#   allocating; node1 is below its watermark, so pages come from node0 and
#   every allocation wakes kswapd1 again.
#
# Expected kill order (most anonymous memory on node1, AM excluded): c_big, c_split.
# usage: spark_repro.sh start|stop   (root; WORK holds the data files, DEV the disk,
#        RIOPS=max when DEV is a real HDD)
set -u
CG=/sys/fs/cgroup/os_test
WORK=${WORK:-/tmp/os_test/data}
HERE=$(cd $(dirname $0) && pwd)
S=${SCALE:-1}

run_in() {	# run_in CONTAINER CMD...: start CMD inside the container's cgroup
	mkdir -p $CG/$1
	sh -c "echo \$\$ > $CG/$1/cgroup.procs; exec ${*:2}" </dev/null >/dev/null 2>&1 &
}

hog() {		# hog CONTAINER NODE GB: allocate on NODE, touch once, hold
	run_in $1 numactl --membind=$2 $WORK/hog $3
}

start() {
	mkdir -p $CG $WORK
	echo "+memory +io" > /sys/fs/cgroup/cgroup.subtree_control
	echo "+memory +io" > $CG/cgroup.subtree_control
	for i in 0 1 2 3 4 5 6 7; do
		[ -s $WORK/f$i ] || dd if=/dev/urandom of=$WORK/f$i bs=1M count=1024 status=none
	done
	gcc -O2 -pthread -o $WORK/hot $HERE/hot.c
	gcc -O2 -o $WORK/hog $HERE/hog.c
	sync; echo 1 > /proc/sys/vm/drop_caches

	# node0: page cache nobody needs, and anonymous memory
	numactl --membind=0 cat $WORK/f4 $WORK/f5 $WORK/f6 $WORK/f7 > /dev/null
	hog c_node0 0 $((10 * S))
	hog c_split 0 $((4 * S))

	# node1: anonymous memory up to ~1.5G free
	hog c_split 1 $((5 * S))
	hog app_000001 1 $((4 * S))
	hog c_big 1 $((12 * S))
	sleep $((60 * S))
	fill=$(( $(awk '/MemFree/{print $4}' /sys/devices/system/node/node1/meminfo) / 1024 / 1024 - ${SLACK1:-8} ))
	[ $fill -gt 0 ] && hog c_big 1 $fill
	# node0 near its watermark too, so node1 cannot simply fall back to it.
	# Bound fills stop above the high watermark (SLACK GB free): below it, a
	# membind allocation that finds nothing to reclaim OOM-kills on that node.
	fill=$(( $(awk '/MemFree/{print $4}' /sys/devices/system/node/node0/meminfo) / 1024 / 1024 - ${SLACK0:-8} ))
	[ $fill -gt 0 ] && hog c_node0 0 $fill
	sleep 30

	# node1 CPUs: hot code pages on a slow disk; like the JVM, not bound to
	# node1 memory (a binding makes the kernel OOM-kill instead of thrash)
	mkdir -p $CG/c_io
	echo "${DEV:-8:0} riops=${RIOPS:-300}" > $CG/c_io/io.max
	for i in $(seq 1 ${PROCS:-16}); do
		run_in c_io numactl --cpunodebind=1 $WORK/hot ${HOT_MB:-2048} 4 $WORK/f0 $WORK/f1
	done

	# executors keep allocating on both nodes' CPUs, no memory binding: each
	# node is pushed to its watermark and neither can absorb the other's
	# allocations (a bound allocation here would OOM-kill instead)
	for n in 1 1 0 0; do
		run_in c_churn numactl --cpunodebind=$n $WORK/hog $((5 * S / 8 + 1)) churn
	done
}

stop() {
	for d in $CG/*/; do
		[ -f $d/cgroup.procs ] && xargs -r kill -9 < $d/cgroup.procs
	done
	sleep 5
	for d in $CG/*/; do rmdir $d 2>/dev/null; done
	rmdir $CG 2>/dev/null
}

case ${1:-} in
start) start ;;
stop) stop ;;
*) echo "usage: $0 start|stop"; exit 2 ;;
esac
