#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

typedef bit<9> egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit <16> etherType;
}

header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<6>  dscp;
    bit<2>  ecn;
    bit<16> totalLen;
    bit<16> identification;
    bit<3> flags;
    bit<13> fragOffset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header UDP_h {
    bit<16> src;
    bit<16> dst;
    bit<16> len;
    bit<16> checksum;
}


struct metadata {
   ip4Addr_t targetAddr; //used for task 1
   bit<32> meter_tag; //used for task 2
}

struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
    UDP_h  udp;
}

/************************************************** ************************
*********************** PARSER *************************** *********
*************************************************** ***********************/

parser MyParser (packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        packet.extract(hdr.ethernet);
        transition select (hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract (hdr.ipv4);
        transition accept;
    }
}

/************************************************** ************************
************ CHECKSUMVERIFICATION *************
*************************************************** ***********************/

control MyVerifyChecksum (inout headers hdr, inout metadata meta) {
    apply {}
}


/************************************************** ************************
************** INGRESSPROCESSING ********************
*************************************************** ***********************/

control MyIngress (inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    direct_meter<bit<32>>(MeterType.packets) my_meter;
    // TODO: this should have been an indirect meter

    action drop () {
        mark_to_drop (standard_metadata);
    }

    action m_action(){
        my_meter.read(meta.meter_tag)
    }

    action ipv4_forward (macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm{
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
    }

    table m_read {
        key = {
            hdr.ethernet.srcAddr: exact;
        }
        actions = {
            m_action;
            NoAction;
        }
        meters = my_meter;
        size = 16384;
    }

    table m_filter {
        key = {
            meta.meter_tag: exact;
        }
        actions = {
            drop;
            NoAction;
        }
        default_action = drop();
        size = 16;
    }

    apply {
        if (hdr.ipv4.isValid ()) {
	        ipv4_lpm.apply();  // TODO: this was not in the slides, but it seems necessary? its not in this case

            standard_metadata.egress_spec = 2;
            m_read.apply();
            m_filter.apply();
        }
    }
}

/************************************************** ************************
**************** EGRESSPROCESSING ********************
*************************************************** ***********************/

control MyEgress (inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {}
}

/************************************************** ************************
************* CHECKSUMCOMPUTATION **************
*************************************************** ***********************/

control MyComputeChecksum (inout headers hdr, inout metadata meta) {
     apply {
        update_checksum (
            hdr.ipv4.isValid (),
            {hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.dscp,
	      hdr.ipv4.ecn,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr},
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/************************************************** ************************
*********************** DEPART *************************** *****
*************************************************** ***********************/

control MyDeparser (packet_out packet, in headers hdr) {
    apply {
        packet.emit (hdr.ethernet);
        packet.emit (hdr.ipv4);
    }
}

/************************************************** ************************
*********************** SWITCH *************************** *****
*************************************************** ***********************/

V1Switch (
MyParser (),
MyVerifyChecksum (),
MyIngress (),
MyEgress (),
MyComputeChecksum (),
MyDeparser ()
)main;

