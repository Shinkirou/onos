//------------------------------------------------------------------------------
// PARSER
//------------------------------------------------------------------------------

parser c_parser(packet_in packet, out headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

    // A P4 parser is described as a state machine, with initial state "start"
    // and final one "accept". Each intermediate state can specify the next
    // state by using a select statement over the header fields extracted.
    state start {
        transition select(standard_metadata.ingress_port) {
            CPU_PORT: parse_packet_out;
            default: parse_ethernet;
        }
    }

    state parse_packet_out {
        packet.extract(hdr.packet_out);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETH_TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_TCP:   parse_tcp;
            IP_PROTO_UDP:   parse_udp;
            IP_PROTO_ICMP:  parse_icmp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        meta.meta.l4_src_port = hdr.tcp.src_port;
        meta.meta.l4_dst_port = hdr.tcp.dst_port;
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        meta.meta.l4_src_port = hdr.udp.src_port;
        meta.meta.l4_dst_port = hdr.udp.dst_port;
        transition accept;
    }

    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }
}
