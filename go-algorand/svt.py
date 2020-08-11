#!/usr/bin/env python3

import json
import os

relay_port_base = 4160
archive_port_base = 5160

def sys(cmd, checked=True):
    print(cmd)
    ret = os.system(cmd)
    if checked and ret != 0:
        raise Exception('cmd "{}" exited with nonzero code: {}'.format(cmd, ret))

def setup_node(name):
    target = 'svtnet/{}'.format(name)
    sys('mkdir -p {}'.format(target))
    sys('cp svtnet/temp/genesis.json {}'.format(target))

def setup_wallet(wid, partition):
    wname = 'node{}'.format(partition)
    target = 'svtnet/{}'.format(wname)
    setup_node(wname)
    sys('cp svtnet/temp/node_config.json {}/config.json'.format(target))
    sys('cp svtnet/temp/node_phonebook.json {}/phonebook.json'.format(target))

    sys('mkdir -p {}/svtnet-v1.0'.format(target))
    sys('cp gen/devnet/Wallet{}.rootkey {}/svtnet-v1.0'.format(wid, target))
    sys('cp gen/devnet/Wallet{}.0.3000000.partkey {}/svtnet-v1.0'.format(wid, target))

    return target

def setup_relay(rid, addr, all_addrs, phonebook, archive=False):
    rname = 'relay{}'.format(rid)
    if archive:
        rname = 'archive{}'.format(rid)

    target = 'svtnet/{}'.format(rname)
    setup_node(rname)

    rconfig = 'svtnet/temp/relay_config.json'
    if archive:
        rconfig = 'svtnet/temp/archive_config.json'
    with open(rconfig) as f:
        cfg = json.load(f)
        cfg['NetAddress'] = addr
        with open('{}/config.json'.format(target), 'w') as g:
            json.dump(cfg, g)

    neighbors = []
    for neighbor in all_addrs:
        if neighbor != addr:
            neighbors.append(neighbor)

    phonebook_copy = {}
    for k in phonebook:
        phonebook_copy[k] = phonebook[k]
    phonebook_copy["Include"] = neighbors

    with open('{}/phonebook.json'.format(target), 'w') as f:
        json.dump(phonebook_copy, f)

    return target

class ExperimentalConfiguration:
    def __init__(self, **kwargs):
        self.NumArchives = kwargs["NumArchives"] # relay, archive
        self.NumRelays = kwargs["NumRelays"]     # relay, non-archive
        self.NumNodes = kwargs["NumNodes"]       # non-relay, non-archive
    def __str__(self):
        return str({'NumArchives': self.NumArchives, 'NumRelays': self.NumRelays, 'NumNodes': self.NumNodes})

EC_5_1_1 = ExperimentalConfiguration(NumNodes=5, NumRelays=1, NumArchives=1)
EC_1_0_1 = ExperimentalConfiguration(NumNodes=1, NumRelays=0, NumArchives=1)
EC_1_1_1 = ExperimentalConfiguration(NumNodes=1, NumRelays=1, NumArchives=1)
EC_3_1_1 = ExperimentalConfiguration(NumNodes=3, NumRelays=1, NumArchives=1)
EC_20_2_1 = ExperimentalConfiguration(NumNodes=20, NumRelays=2, NumArchives=1)
EC_10_1_4 = ExperimentalConfiguration(NumNodes=10, NumRelays=1, NumArchives=4)

def setup(config=EC_5_1_1, fastproto=False):
    print('Setting up experiment with configuration', config, 'fastproto =', fastproto)

    sys('killall -9 algod', checked=False) # TODO && sleep for some seconds
    sys('killall -9 kmd', checked=False)   # TODO && sleep for some seconds

    sys('make')
    sys('rm -r svtnet', checked=False)
    sys('mkdir svtnet')

    sys('mkdir svtnet/temp')

    relay_ports = []
    archive_ports = []

    for i in range(config.NumRelays):
        relay_ports.append(relay_port_base+i)
    for i in range(config.NumArchives):
        archive_ports.append(archive_port_base+i)

    relay_addrs = []
    for port in relay_ports:
        relay_addrs.append('127.0.0.1:{}'.format(port))

    archive_addrs = []
    for port in archive_ports:
        archive_addrs.append('127.0.0.1:{}'.format(port))

    all_addrs = relay_addrs + archive_addrs

    ## setup genesis.json
    with open('gen/devnet/genesis.json') as f:
        gen = json.load(f)
        gen['network'] = 'svtnet'
        gen['proto'] = 'https://github.com/algorandfoundation/specs/tree/5615adc36bad610c7f165fa2967f4ecfa75125f0'
        if fastproto:
            gen['proto'] = 'consensus-fast-SVT-' + gen['proto']
        with open('svtnet/temp/genesis.json', 'w') as g:
            json.dump(gen, g)

    ## setup config.json
    node_cfg = {
        "Archival": False,
        "DeadlockDetection": -1,
        "IncomingConnectionsLimit": 10000,
        "BroadcastConnectionsLimit": 10000,
        "GossipFanout": config.NumRelays + config.NumArchives,
    }
    with open('svtnet/temp/node_config.json', 'w') as f:
        json.dump(node_cfg, f)

    relay_cfg = {
        "Archival": False,
        "DeadlockDetection": -1,
        "IncomingConnectionsLimit": 10000,
        "BroadcastConnectionsLimit": 10000,
        "GossipFanout": config.NumRelays + config.NumArchives - 1,
        "NetAddress": "PARAMETER",
    }
    with open('svtnet/temp/relay_config.json', 'w') as f:
        json.dump(relay_cfg, f)

    archive_cfg = {}
    for k in relay_cfg:
        archive_cfg[k] = relay_cfg[k]
    archive_cfg["Archival"] = True
    with open('svtnet/temp/archive_config.json', 'w') as f:
        json.dump(archive_cfg, f)

    ## setup phonebook.json
    phonebook = {
        "Include": "PARAMETER",
    }
    phonebook["Include"] = all_addrs
    with open('svtnet/temp/node_phonebook.json', 'w') as f:
        json.dump(phonebook, f)

    wids = range(1, 21)
    pids = list(range(1, config.NumNodes+1)) * len(wids)
    rids = range(1, config.NumRelays+1)
    aids = range(1, config.NumArchives+1)

    subnodes = []

    for i, rid in enumerate(rids):
        addr = relay_addrs[i]
        subnodes.append(setup_relay(rid, addr, all_addrs, phonebook))

    for i, aid in enumerate(aids):
        addr = archive_addrs[i]
        subnodes.append(setup_relay(aid, addr, all_addrs, phonebook, archive=True))

    for i, wid in enumerate(wids):
        part = pids[i]
        nwid = setup_wallet(wid, part)
        if nwid not in subnodes:
            subnodes.append(nwid)

    return subnodes

EC_REMOTE1 = EC_10_1_4
# subnodes = setup(EC_1_1_1, True)
subnodes = setup(EC_REMOTE1, False)


prep = True

if not prep:
    sys('./launch-nodes.sh {}'.format(' '.join(subnodes)))

    sys('mkdir svtnet/results')

    for subnode in subnodes:
        name = subnode.replace('svtnet/', '')
        sys('grep EXTPS {}/node.log > svtnet/results/{}.log'.format(subnode, name))
        sys('cp {}/meta.json svtnet/results/{}.json'.format(subnode, name), checked=False)
