#!/usr/bin/env python3

import json
import os
import sys

relay_port_base = 4160
archive_port_base = 5160

invfile = sys.argv[1]

def parse_inv(invfile):
    ns = []
    rs = []
    ips = {}

    with open(invfile) as f:
        state = 0

        for line in f:
            if state == 0:
                if not line.startswith('[name_'):
                    continue
                key = line.strip().replace('[name_', '').replace(']', '')
                state = 1
            elif state == 1:
                state = 0
                if key.startswith('n'):
                    ns.append(key)
                    ips[key] = line.strip()
                elif key.startswith('r'):
                    rs.append(key)
                    ips[key] = line.strip()

    return ns, rs, ips

(ns, rs, ips) = parse_inv(invfile)

print(ns, rs)
print(ips)

def sys(cmd, checked=True):
    print(cmd)
    ret = os.system(cmd)
    if checked and ret != 0:
        raise Exception('cmd "{}" exited with nonzero code: {}'.format(cmd, ret))

sys('rm -r rsvtnet', checked=False)
sys('cp -R svtnet rsvtnet')

fnames = os.listdir("rsvtnet")

numn = len([x for x in fnames if x.startswith("node")])
numr = len([x for x in fnames if x.startswith("relay")])
numa = len([x for x in fnames if x.startswith("archive")])

if numn != len(ns):
    print("{} != {}", numn, len(ns))
    raise Exception("incorrect # physical nodes")

if numa + numr != len(rs):
    print("{} + {} != {}", numa, numr, len(rs))
    raise Exception("incorrect # physical relays")
    
nnames = ["node" + str(x) for x in range(1, numn+1)]
rnames = ["relay" + str(x) for x in range(1, numr+1)]
anames = ["archive" + str(x) for x in range(1, numa+1)]

namemap = {}
ipmap = {}
for i, nname in enumerate(nnames):
    namemap[nname] = ns[i]
    ipmap[nname] = ips[ns[i]]
for i, rname in enumerate(rnames):
    namemap[rname] = rs[i]
    # ipmap[rname] = ips[rs[i]] + ":" + str(relay_port_base + i)
    ipmap[rname] = ips[rs[i]] + ":" + "4560"
for i, aname in enumerate(anames):
    namemap[aname] = rs[i + numr]
    # ipmap[aname] = ips[rs[i + numr]] + ":" + str(archive_port_base + i)
    ipmap[aname] = ips[rs[i + numr]] + ":" + "4560"

inv_ipmap = {}
for fname in rnames + anames:
    with open("svtnet/{}/config.json".format(fname)) as f:
        with open("rsvtnet/{}/config.json".format(fname), "w") as g:
            cfg = json.load(f)
            ip = cfg["NetAddress"]
            inv_ipmap[ip] = fname
            cfg["NetAddress"] = ":4560"
            json.dump(cfg, g)

for fname in nnames + rnames + anames:
    with open("svtnet/{}/phonebook.json".format(fname)) as f:
        with open("rsvtnet/{}/phonebook.json".format(fname), "w") as g:
            pb = json.load(f)
            old = pb['Include']
            new = [ipmap[inv_ipmap[x]] for x in old]
            pb['Include'] = new
            json.dump(pb, g)

print(namemap)
print(ipmap)

with open('rsvtnet/names.json', 'w') as f:
    json.dump(namemap, f)

sys('mkdir rsvtnet/bin')

bins = ['algod', 'carpenter', 'goal', 'kmd', 'svtload']

for bname in bins:
    sys('cp ~/go/bin/{} rsvtnet/bin'.format(bname))
