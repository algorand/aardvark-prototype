#!/bin/bash

numactl -C 0-0 -- nohup go test -v -run TestTimeArchive -cpuprofile abench1.out -timeout 4h -count 3 > aout1.txt &
