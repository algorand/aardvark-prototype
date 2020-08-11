#!/bin/bash

echo "launching subprocesses"

count=0
for subdir in "$@"; do
    svtload --datadir "$subdir" &
    pids[${count}]=$!
    ((count++))
done

echo "waiting for subprocess termination..."

for pid in ${pids[*]}; do
    wait $pid
done
