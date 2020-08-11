#!/bin/bash

nohup go test -v -run TestWorkloadGen -cpuprofile gen.out -timeout 5h && nohup go test -v -run TestTimeWorkload -cpuprofile bench.out -timeout 1h -count 5 &
