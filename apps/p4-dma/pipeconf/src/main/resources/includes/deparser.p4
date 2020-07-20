control c_deparser(packet_out packet, in headers_t hdr) {
	
	apply {
		packet.emit(hdr.ethernet);
		packet.emit(hdr.ipv4);
		packet.emit(hdr.tcp);
		packet.emit(hdr.udp);
	}
}