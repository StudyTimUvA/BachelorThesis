/* Include P4 core library */
#include <core.p4>
/* Include V1 Model switch architecture */
#include <v1model.p4>

/* Describes the format of an Ethernet header */
header Ethernet_h {
    bit<48> dst;
    bit<48> src;
    bit<16> typ;
}

/*
Structure of user metadata.
No user metadata is needed for this example so the struct is empty.
*/
struct user_metadata_t {}
/* Structure of parsed headers. */
struct headers_t {
    Ethernet_h ethernet;
}

/* The parser describes the state machine used to parse packet headers. */
parser MyParser(packet_in pkt, out headers_t hdr, inout user_metadata_t umd, inout standard_metadata_t smd) {
    /* The state maachine always begins parsing with the start state */
    state start {
        /* Fills in the values of the Ethernet header and sets the header as valid. */
        pkt.extract(hdr.ethernet);
        /* Packet parsing terminates when the state machine tranisions to the accept of reject state */
        transition accept;
    }
}

/* This contol block is not used for the lab. */
control MyVerifyChecksum(inout headers_t hdr, inout user_metadata_t umd) {
    apply {}
}

/*
Control flow prior to egress port selection.
egress_spec can be assigned a value to control which output port a packet will go to.
egress_port should not be accessed.
 */
control MyIngress(inout headers_t hdr, inout user_metadata_t umd, inout standard_metadata_t smd) {
    /* An action that takes the desired egress port as an argument. */
    action set_egress(bit<9> port) {
        smd.egress_spec = port;
    }
    /* An action that will cause the packet to be dropped. */
    action drop() {
        mark_to_drop(smd);
    }
    table forwarding {
        /* Values that will be used to look up an entry. */
        key = { hdr.ethernet.dst: exact; }
        /* All possible actions that may result from a lookup or table miss. */
        actions = {
            set_egress;
            drop;
        }
        /* The action to take when the table does not find a match for the supplied key. */
        default_action = drop;
    }
    apply {
        /* Apply the forawrding table to all packets. */
        forwarding.apply();
        // Don't send packets out the same interface it entered on.
        if (smd.egress_spec == smd.ingress_port) {
            mark_to_drop(smd);
        }
    }
}

/*
Control flow after egress port selection.
egress_spec should not be modified. egress_port can be read but not modified. The packet can still be dropped.
*/
control MyEgress(inout headers_t hdr, inout user_metadata_t umd, inout standard_metadata_t smd) {
    apply {}
}

/* This contol block is not used for the lab. */
control MyComputeChecksum(inout headers_t hdr, inout user_metadata_t umd) {
    apply {}
}

/* The deparser constructs the outgoing packet by reassembling headers in the order specified. */
control MyDeparser(packet_out pkt, in headers_t hdr) {
    apply {
        /* Emitting a header appends the header to the out going packet only if the header is valid. */
        pkt.emit(hdr.ethernet);
    }
}

/* This instantiate the V1 Model Switch */.
V1Switch(
 MyParser(),
 MyVerifyChecksum(),
 MyIngress(),
 MyEgress(),
 MyComputeChecksum(),
 MyDeparser()
) main;
