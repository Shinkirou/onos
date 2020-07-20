parser c_parser(packet_in packet, out headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

	state start {
		transition parse_ethernet;
	}

	state parse_ethernet {
		packet.extract(hdr.ethernet);
		transition select(hdr.ethernet.ether_type) {
			TYPE_IPV4: parse_ipv4;
			default: accept;
		}
	}

	state parse_ipv4 {
		packet.extract(hdr.ipv4);
		transition select(hdr.ipv4.protocol) {
			IP_PROTO_TCP: parse_tcp;
			IP_PROTO_UDP: parse_udp;
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
}