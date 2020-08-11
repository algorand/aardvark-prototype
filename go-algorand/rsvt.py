#!/usr/bin/env python3

import json
import multiprocessing
import os
import sys

invfile = sys.argv[1]
keyfile = sys.argv[2]

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

lnames = os.listdir('rsvtnet')
lnames = [x for x in lnames if 'node' in x or 'relay' in x or 'archive' in x]
if len(lnames) == 0:
    print('no lnames')

with open('rsvtnet/names.json') as f:
    namemap = json.load(f)

print(lnames)
print(namemap)

sshopts = '-i {} -o "StrictHostKeyChecking=no" -o "UserKnownHostsFile=/dev/null"'.format(keyfile)
sshcmd = '"ssh {}"'.format(sshopts)

prepcmd = ''
for lname in lnames:
    rname = namemap[lname]
    prepcmd += 'ssh {} ubuntu@{} "rm -r ~/bin; rm -r ~/data; mkdir -p ~/bin; mkdir -p ~/data" &\n'.format(sshopts, ips[rname])
prepcmd += 'wait'
sys(prepcmd)

cpcmd = ''
for lname in lnames:
    rname = namemap[lname]
    cpcmd += 'rsync -avz -e {} rsvtnet/bin ubuntu@{}:~/ &\n'.format(sshcmd, ips[rname])
    cpcmd += 'rsync -avz -e {} rsvtnet/{} ubuntu@{}:~/data &\n'.format(sshcmd, lname, ips[rname])
cpcmd += 'wait\n'
sys(cpcmd)

spoolcmd = ''
for lname in lnames:
    rname = namemap[lname]
    spoolcmd += 'ssh {} ubuntu@{} "touch ~/data/{}/node.log; tail -f ~/data/{}/node.log | grep EXTPS > ~/experiment.log" &\n'.format(sshopts, ips[rname], lname, lname)
spoolcmd += 'wait'
def expspool():
    sys(spoolcmd)
spoolps = multiprocessing.Process(target=expspool)
spoolps.start()

execmd = ''
for lname in lnames:
    cut = '--cut'
    if lname in ['node1', 'node2', 'node3', 'node4', 'node5']:
        cut = ''
    rname = namemap[lname]
    execmd += 'ssh {} ubuntu@{} "killall -9 algod; killall -9 kmd; ~/bin/svtload --datadir ~/data/* {}" &\n'.format(sshopts, ips[rname], cut)
execmd += 'wait'
sys(execmd)

kspoolcmd = ''
for lname in lnames:
    rname = namemap[lname]
    kspoolcmd += 'ssh {} ubuntu@{} "pkill tail -P $$" &\n'.format(sshopts, ips[rname])
kspoolcmd += 'wait'
sys(kspoolcmd)

# spoolps.terminate()

sys('mkdir rsvtnet/results')

# ppcmd = ''
# for lname in lnames:
#     rname = namemap[lname]
#     ppcmd += 'ssh {} ubuntu@{} "grep EXTPS ~/data/*/node.log > ~/experiment.log" &\n'.format(sshopts, ips[rname])
# ppcmd += 'wait'
# sys(ppcmd)


rescmd = ''
for lname in lnames:
    rname = namemap[lname]
    rescmd += 'rsync -avz -e {} ubuntu@{}:~/data/{}/meta.json rsvtnet/results/{}.json &\n'.format(sshcmd, ips[rname], lname, lname)
    rescmd += 'rsync -avz -e {} ubuntu@{}:~/experiment.log rsvtnet/results/{}.log &\n'.format(sshcmd, ips[rname], lname)
rescmd += 'wait'
sys(rescmd)

