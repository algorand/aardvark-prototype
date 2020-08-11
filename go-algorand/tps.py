#!/usr/bin/env python3

import datetime
import json
import os
import sys

def strptime(x):
    if x.endswith("Z"):
        for i in range(len(x)):
            try:
                return datetime.datetime.strptime(x[:-i], "%Y-%m-%dT%H:%M:%S.%f")
            except:
                pass
        raise Exception("can't parse date {}".format(x))
    return datetime.datetime.strptime(x[:-9], "%Y-%m-%dT%H:%M:%S.%f")

dirname = sys.argv[1]
print(os.listdir(dirname))

targets = {}
for fname in os.listdir(dirname):
    fname = os.path.join(dirname, fname)
    fname = fname.replace('.log', '')
    fname = fname.replace('.json', '')
    targets[fname] = True

targetlist = sorted([x for x in targets])
targets = targetlist

maxstart = 0
minend = 0

for target in targetlist:
    try:
        with open(target + ".json") as f:
            meta = json.load(f)
            print(meta)

            if maxstart == 0:
                maxstart = [int(meta['FuzzStartRound']), meta['FuzzStart']]
            if int(meta['FuzzStartRound']) > maxstart[0]:
                maxstart = [int(meta['FuzzStartRound']), meta['FuzzStart']]

            if minend == 0:
                minend = [int(meta['FuzzEndRound']), meta['FuzzEnd']]
            if int(meta['FuzzEndRound']) < minend[0]:
                minend = [int(meta['FuzzEndRound']), meta['FuzzEnd']]
            
    except:
        continue

maxstart[1] = strptime(maxstart[1])
minend[1] = strptime(minend[1])
duration = minend[1]-maxstart[ 1]

for target in targetlist:
    total = 0
    with open(target + ".log") as f:
        for line in f:
            if "AddValidatedBlock" not in line:
                continue
            data = json.loads(line)

            if int(data["rnd"]) <= maxstart[0] or int(data["rnd"]) >= minend[0]:
                continue

            total += int(data['txns'])
    print(target, "reports", total, "total transactions, or", total/duration.total_seconds(), "transactions per second.")
