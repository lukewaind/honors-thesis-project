/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_DNP3 = 0x564;
const bit<8> TYPE_TCP = 0x06;

const bit<48> INTERVAL = 0xDBBA0; // 0.9 seconds in microseconds
const int<16> PACKETSININTERVAL = 1;

register<bit<48>>(1024) intervalStart;
register<int<16>>(1024) intervalCount;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    bit<160> tcp;
}

header dnp3_t {
    bit<160> tcp;
    bit<16> start;
    bit<8> length;
    bit<8> linkControl;
    bit<16> dst;
    bit<16> src;
    bit<16> crc;
    bit<8> transportControl;
    bit<8> appControl;
    bit<8> functionCode;
}

header dnp3_read_t {
    bit<24> data;
}

header dnp3_response_t {
    bit<8> qualifier;
    bit<16> quantity;
    bit<40> data;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t      ethernet;
    ipv4_t          ipv4;
    tcp_t           tcp;
    dnp3_t          dnp3;
    dnp3_read_t     dnp3_read;
    dnp3_response_t dnp3_response;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_TCP: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.dnp3);
        transition select(packet.lookahead<bit<16>>()) {
            TYPE_DNP3: parse_dnp3;
            default: accept;
        }
    }

    state parse_dnp3 {
        packet.extract(hdr.dnp3);
        transition select (hdr.dnp3.functionCode) {
            0x01: parse_dnp3_read;
            0x81: parse_dnp3_response;
            default: accept;
        }
    }

    state parse_dnp3_read {
        packet.extract(hdr.dnp3_read);
        transition accept;
    }

    state parse_dnp3_response {
        packet.extract(hdr.dnp3_response);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        
        if (hdr.ipv4.isValid()) {
            if (hdr.dnp3.isValid()) {
                bit<1> todrop = 0; // if packet should be dropped
                // Length check
                bit<16> DNP3Len;
                // DNP3 Length = total length - IP header length - TCP header length
                DNP3Len = hdr.ipv4.totalLen - (((bit<16>)hdr.ipv4.ihl) << 2) - 20;
                if (DNP3Len != (bit<16>)hdr.dnp3.length) {
                    todrop = 1;
                }

                // Outstation write check
                if (hdr.dnp3.functionCode == 0x02) {
                    bit<32> registerNum;
                    hash(registerNum, HashAlgorithm.crc16, (bit<1>)0, {hdr.ipv4.srcAddr}, (bit<10>)1023);
                    bit<48> arrivalTime = standard_metadata.ingress_global_timestamp;
                    bit<48> intervalStartVal;
                    intervalStart.read(intervalStartVal, registerNum);
                    // check if interval is expired
                    if (arrivalTime - intervalStartVal > INTERVAL) {
                        intervalStart.write(registerNum, arrivalTime);
                        intervalCount.write(registerNum, 1);
                    } else {
                        int<16> intervalCountVal;
                        intervalCount.read(intervalCountVal, registerNum);
                        intervalCount.write(registerNum, intervalCountVal + 1);
                        if (intervalCountVal + 1 > PACKETSININTERVAL) {
                            todrop = 1;
                        }
                    }
                }
                if (todrop == 1) {
                    drop();
                } else {
                    ipv4_lpm.apply();
                }
            } else {
                ipv4_lpm.apply();
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.dnp3);
        packet.emit(hdr.dnp3_read);
        packet.emit(hdr.dnp3_response);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
