#!/usr/bin/env python3

from datetime import datetime, timedelta
import os
import re
import sys
import csv

DATA_DIR = "./data"

files = os.listdir(DATA_DIR)

timedata = {}

for fname in files:
    cores = int(fname[len("out"):-4])
    with open(os.path.join(DATA_DIR, fname)) as f:
        for line in f:
            if "time" in line and "readonly" not in line:
                fields = line.split()
                label = fields[0]
                fields = fields[2].split('.')
                try:
                    t = datetime.strptime(fields[0],"%Mm%S")
                except:
                    t = datetime.strptime(fields[0],"%S")
                rounding = 0
                if int(fields[1][1]) >= 5:
                    rounding = 1
                delta = timedelta(hours=t.hour, minutes=t.minute, seconds=t.second)

                key = (label, cores)
                if key not in timedata:
                    timedata[key] = []
                timedata[key].append(int(delta.total_seconds() + rounding))

writer = csv.writer(sys.stdout)
for key in timedata:
    for datum in timedata[key]:
        writer.writerow([key[0], key[1], datum])
