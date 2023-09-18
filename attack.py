#!/usr/bin/env python3
import sys
from scapy.all import *
from scapy.all import Ether, IP, TCP, Raw, get_if_list, get_if_hwaddr, get_if_addr, sendpfast

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

iface = get_if()
mac = get_if_hwaddr(iface)
dst = get_if_addr(iface)
src = sys.argv[1]

pkt = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
pkt = pkt /IP(dst=dst,src=src)/TCP(dport=20000)
pkt = pkt /Raw(bytes.fromhex('056415000000000000000000020000000000000000'))

while True:
    print(sendpfast(pkt, iface=iface, mbps=int(sys.argv[2]) / 1000.0, loop=10000, parse_results=True)['mbps'])
