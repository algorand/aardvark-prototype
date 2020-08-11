#!/bin/bash

numactl -C 32-63 -- nohup go test -v -run TestTimeWorkload -cpuprofile bench32.out -timeout 4h -count 3 > out32.txt &
numactl -C 16-31 -- nohup go test -v -run TestTimeWorkload -cpuprofile bench16.out -timeout 4h -count 3 > out16.txt &
numactl -C 8-15 -- nohup go test -v -run TestTimeWorkload -cpuprofile bench8.out -timeout 4h -count 3 > out8.txt &
numactl -C 4-7 -- nohup go test -v -run TestTimeWorkload -cpuprofile bench4.out -timeout 4h -count 3 > out4.txt &
numactl -C 2-3 -- nohup go test -v -run TestTimeWorkload -cpuprofile bench2.out -timeout 4h -count 3 > out2.txt &
numactl -C 1-1 -- nohup go test -v -run TestTimeWorkload -cpuprofile bench1.out -timeout 4h -count 3 > out1.txt &
