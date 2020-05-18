//------------------------------------------------------------------------------
// HEADERS
//------------------------------------------------------------------------------

header ethernet_t {
	bit<48> dst_addr;
	bit<48> src_addr;
	bit<16> ether_type;
}

header ipv4_t {
	bit<4>  version;
	bit<4>  ihl;
	bit<8>  diffserv;
	bit<16> len;
	bit<16> identification;
	bit<3>  flags;
	bit<13> frag_offset;
	bit<8>  ttl;
	bit<8>  protocol;
	bit<16> hdr_checksum;
	bit<32> src_addr;
	bit<32> dst_addr;
}

header tcp_t {
	bit<16> src_port;
	bit<16> dst_port;
	bit<32> seq_no;
	bit<32> ack_no;
	bit<4>  data_offset;
	bit<3>  res;
	bit<3>  ecn;
	bit<6>  ctrl;
	bit<16> window;
	bit<16> checksum;
	bit<16> urgent_ptr;
}

header udp_t {
	bit<16> src_port;
	bit<16> dst_port;
	bit<16> length_;
	bit<16> checksum;
}

header icmp_t {
	bit<8> type;
	bit<8> code;
	bit<16> hdrChecksum;
}

// Packet-in header. Prepended to packets sent to the controller and used to
// carry the original ingress port where the packet was received.
@controller_header("packet_in")
header packet_in_header_t {
	bit<9>  ingress_port;
	bit<64> timestamp;
	bit<32> ip_src;
	bit<32> ip_dst;
	bit<9>  ip_proto;
	bit<16> port_src;
	bit<16> port_dst;
	bit<12> tcp_flags;
	bit<9>  icmp_type;
	bit<9>  icmp_code;
	bit<32> cm_ip;
	bit<32> cm_5t;
	bit<32> bm_src;
	bit<32> bm_dst;
	bit<32> ams;
	bit<9>  mv;
	bit<7>  _padding;
}

// Packet-out header. Prepended to packets received by the controller and used
// to tell the switch on which port this packet should be forwarded.
@controller_header("packet_out")
header packet_out_header_t {
	bit<9> egress_port;
	bit<7> _padding;
}

struct headers_t {
	ethernet_t          ethernet;
	ipv4_t              ipv4;
	tcp_t               tcp;
	udp_t               udp;
	icmp_t              icmp;
	packet_out_header_t packet_out;
	packet_in_header_t  packet_in;
}

header meta_t {
	bit<16> l4_src_port;
	bit<16> l4_dst_port;
}

header cm_meta_t {
	bit<32> hash_ip_0;
	bit<32> hash_ip_1;
	bit<32> hash_ip_2;
	bit<32> sketch_ip_0;
	bit<32> sketch_ip_1;
	bit<32> sketch_ip_2;
	bit<32> sketch_ip_final;
	bit<32> hash_5t_0;
	bit<32> hash_5t_1;
	bit<32> hash_5t_2;
	bit<32> sketch_5t_0;
	bit<32> sketch_5t_1;
	bit<32> sketch_5t_2;
	bit<32> sketch_5t_final;
}

header bm_meta_t {
	bit<32> hash_0;
	bit<32> hash_1;
	bit<32> hash_2;
	bit<32> sketch_0;
	bit<32> sketch_1;
	bit<32> sketch_2;
}

header k_ary_meta_t {
	bit<32> t_interval;
	bit<32> sum;
	bit<32> median;
	bit<32> hash_0;
	bit<32> hash_1;
	bit<32> hash_2;
	bit<32> hash_3;
	bit<32> hash_4;
	bit<32> sketch_0;
	bit<32> sketch_1;
	bit<32> sketch_2;
	bit<32> sketch_3;
	bit<32> sketch_4;
	bit<32> sketch_old_0;
	bit<32> sketch_old_1;
	bit<32> sketch_old_2;
	bit<32> sketch_old_3;
	bit<32> sketch_old_4;    
	bit<32> forecast_0;
	bit<32> forecast_1;
	bit<32> forecast_2;
	bit<32> forecast_3;
	bit<32> forecast_4;
	bit<32> error_0;
	bit<32> error_1;
	bit<32> error_2;
	bit<32> error_3;
	bit<32> error_4;
	bit<32> est_row_0;
	bit<32> est_row_1;
	bit<32> est_row_2;
	bit<32> est_row_3;
	bit<32> est_row_4;
	bit<32> est_F2_sum_0;
	bit<32> est_F2_sum_1;
	bit<32> est_F2_sum_2;
	bit<32> est_F2_sum_3;
	bit<32> est_F2_sum_4;    
}

header ams_meta_t {
	bit<32> hash_0;
	bit<32> hash_1;
	bit<32> hash_2;
	bit<32> hash_3;
	bit<32> hash_g_0;
	bit<32> hash_g_1;
	bit<32> hash_g_2;
	bit<32> hash_g_3;
	bit<32> sketch_0;
	bit<32> sketch_1;
	bit<32> sketch_2;
	bit<32> sketch_3;
	bit<32> sum_0;
	bit<32> sum_1;
	bit<32> sum_2;
	bit<32> sum_3;
	bit<32> sketch_final;
}

header mv_meta_t {
    bit<32> hash;
    bit<64> temp_key;
    int<32> temp_count;
    int<32> temp_sum;
}

header threshold_meta_t {
	bit<32> hash_flow;
	bit<32> flow_traffic;
	bit<32> flow_global_traffic;
	bit<32> global_traffic;
	bit<48> flow_time;

}

struct metadata_t {
	meta_t 					meta;
	cm_meta_t 				cm;
	bm_meta_t 				bm;
	k_ary_meta_t 			k_ary;
	ams_meta_t 				ams;
	mv_meta_t 				mv;
	threshold_meta_t		threshold;
}
