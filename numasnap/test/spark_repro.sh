#!/bin/bash
# Reproduce the Spark hang: one NUMA node full of executor memory, reclaim
# finds nothing but hot code pages, frees them, reads them back, and the host
# stalls. Everything runs in cgroups under /sys/fs/cgroup/os_test.
#
#   c_big       node1: fills it to 8G free             the one to kill
#   app_000001  node1: 32G                             AM, skipped by snapkill
#   c_node0     node0: fills it to 8G free             node0 cannot take node1's load
#   c_io        hot: executes pages of f0, f1 at random  JVM code pages
#   c_churn     hog churn: allocate, touch, free 6G     executors still allocating
#
# usage: spark_repro.sh start|stop   (root; WORK holds the data files, on a slow disk)
set -u
CG=/sys/fs/cgroup/os_test
WORK=${WORK:-/mnt/disk/0/os_test/data}
HERE=$(cd $(dirname $0) && pwd)

run_in() {	# run_in CONTAINER CMD...: start CMD in the container's cgroup
	mkdir -p $CG/$1
	sh -c "echo \$\$ > $CG/$1/cgroup.procs; exec ${*:2}" </dev/null >/dev/null 2>&1 &
}

free_gb() {	# free_gb NODE
	awk '/MemFree/{print int($4 / 1048576)}' /sys/devices/system/node/node$1/meminfo
}

hold() {	# hold CONTAINER NODE GB: GB of anonymous memory on NODE, wait until touched
	run_in $1 numactl --membind=$2 $WORK/hog $3
	while sleep 5; [ $(( $(cat $CG/$1/memory.current) >> 30 )) -lt $3 ]; do :; done
}

fill() {	# fill CONTAINER NODE: hold what NODE has free but 8G
	# Bound memory must stay above the watermark: below it, a membind
	# allocation with nothing to reclaim is OOM-killed instead of thrashing.
	hold $1 $2 $(( $(free_gb $2) - 8 ))
}

start() {
	mkdir -p $CG $WORK
	echo +memory > /sys/fs/cgroup/cgroup.subtree_control
	echo +memory > $CG/cgroup.subtree_control
	for f in f0 f1; do
		[ -s $WORK/$f ] || dd if=/dev/urandom of=$WORK/$f bs=1M count=1024 status=none
	done
	gcc -O2 -pthread -o $WORK/hot $HERE/hot.c
	gcc -O2 -o $WORK/hog $HERE/hog.c
	sync; echo 1 > /proc/sys/vm/drop_caches

	# 1. both nodes full of anonymous memory
	hold app_000001 1 32
	fill c_big 1
	fill c_node0 0

	# 2. JVM code pages, on node1 CPUs; memory not bound, like the JVM
	for i in $(seq 16); do
		run_in c_io numactl --cpunodebind=1 $WORK/hot 2048 4 $WORK/f0 $WORK/f1
	done

	# 3. executors keep allocating on both nodes: reclaim can only take code pages
	for n in 1 1 0 0; do
		run_in c_churn numactl --cpunodebind=$n $WORK/hog 6 churn
	done
}

stop() {
	for d in $CG/*/; do
		[ -f $d/cgroup.procs ] && xargs -r kill -9 < $d/cgroup.procs
	done
	sleep 5
	rmdir $CG/*/ $CG 2>/dev/null
}

case ${1:-} in
start) start ;;
stop) stop ;;
*) echo "usage: $0 start|stop"; exit 2 ;;
esac
