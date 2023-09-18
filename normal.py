#!/usr/bin/env python3
import sys
import time
import struct
import socket
from scapy.fields import *
from scapy.all import (Packet,
    Ether,
    IP,
    TCP,
    Raw,
    IPOption,
    sniff,
    get_if_list,
    get_if_hwaddr,
    get_if_addr,
    sendp)
from scapy.layers.inet import _IPOption_HDR

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

class IPOption_MRI(IPOption):
    name = "MRI"
    option = 31
    fields_desc = [ _IPOption_HDR,
                    FieldLenField("length", None, fmt="B",
                                  length_of="swids",
                                  adjust=lambda pkt,l:l+4),
                    ShortField("count", 0),
                    FieldListField("swids",
                                   [],
                                   IntField("", 0),
                                   length_from=lambda pkt:pkt.count*4) ]

iface = get_if()
mac = get_if_hwaddr(iface)
src = get_if_addr(iface)
dst = socket.gethostbyname(sys.argv[1])
seq = 0

pkt = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
pkt = pkt /IP(dst=dst,src=src)/TCP(dport=20000)
pkt = pkt /Raw(bytes.fromhex('056415000000000000000000020000000000000000'))

while True:
    start_time = time.time()
    raw_bytes = pkt[Raw].load
    pkt[Raw].load = raw_bytes[:3] + struct.pack('d', time.time()) + raw_bytes[11:]
    pkt[IP].seq = seq
    seq += 1
    sendp(pkt)
    Packet.show2(pkt)
    end_time = time.time()
    time.sleep(max(0, 1 - (end_time - start_time)))
