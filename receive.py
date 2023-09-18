#!/usr/bin/env python3
import os
import sys
import time
import struct

from scapy.all import (
    Ether,
    IP,
    TCP,
    Raw,
    FieldLenField,
    FieldListField,
    IntField,
    IPOption,
    ShortField,
    get_if_list,
    sniff,
    sendpfast
)
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

total_delay = 0
packets = 0

def handle_pkt(pkt):
    if TCP in pkt and pkt[TCP].dport == 20000 and pkt[IP].src != "10.0.1.1":
        global total_delay
        global packets
        send_time = struct.unpack('d', pkt[Raw].load[3:11])[0]
        delay = time.time() - send_time
        total_delay += delay
        packets += 1
        print('packet', packets, 'received. Delay:', delay)

def main():
    global total_delay
    global packets
    packetsResults = []
    delayResults = []
    for i in range(10):
        ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
        iface = ifaces[0]
        # startPkt = [Ether()/IP(dst="10.0."+str(x)+"."+str(x), src="10.0.6.6")/TCP() for x in range(2,6)]
        # sendpfast(startPkt)
        print("starting test", i+1)
        print("sniffing on %s" % iface)
        sys.stdout.flush()
        sniff(iface = iface,
            prn = lambda x: handle_pkt(x),
            filter="tcp port 20000 and not host 10.0.1.1",
            timeout=60)
        packetsResults.append(packets)
        delayResults.append(total_delay / packets)
        packets = 0
        total_delay = 0
        time.sleep(4)
        
    for i in range(10):
        print('test', i+1, 'complete.\npackets received:', packetsResults[i], '\ntotal delay:', delayResults[i])

if __name__ == '__main__':
    main()
