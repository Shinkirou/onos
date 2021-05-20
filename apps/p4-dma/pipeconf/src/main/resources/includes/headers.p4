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
    bit<32> cm_ip_cnt;
    bit<32> cm_ip_len;
    bit<32> cm_ip_port_21_cnt;
    bit<32> cm_ip_port_21_len;
    bit<32> cm_ip_port_22_cnt;
    bit<32> cm_ip_port_22_len;
    bit<32> cm_ip_port_80_cnt;
    bit<32> cm_ip_port_80_len;
    bit<32> cm_ip_tcp_syn_cnt;
    bit<32> cm_ip_tcp_syn_len;
    bit<32> cm_ip_tcp_ack_cnt;
    bit<32> cm_ip_tcp_ack_len;
    bit<32> cm_ip_tcp_rst_cnt;
    bit<32> cm_ip_tcp_rst_len;
    bit<32> cm_ip_icmp_cnt;
    bit<32> cm_ip_icmp_len;
    bit<32> bm_ip_src;
    bit<32> bm_ip_dst;
    bit<32> bm_ip_src_port_src;
    bit<32> bm_ip_src_port_dst;
    bit<32> bm_ip_dst_port_src;
    bit<32> bm_ip_dst_port_dst;
    bit<32> ams;
    bit<9>  mv;
    bit<6>  _padding;
}

// Packet-out header. Prepended to packets received by the controller and used
// to tell the switch on which port this packet should be forwarded.
@controller_header("packet_out")
header packet_out_header_t {
    bit<9> egress_port;
    bit<7> _padding;
}

header meta_t {
    bit<32> length;
    bit<16> l4_src_port;
    bit<16> l4_dst_port;
}

header hash_meta_t {
    bit<32> ip_0;
    bit<32> ip_1;
    bit<32> ip_2;
    bit<32> ip_port_dst_0;
    bit<32> ip_port_dst_1;
    bit<32> ip_port_dst_2;
    bit<32> ip_tcp_flags_0;
    bit<32> ip_tcp_flags_1;
    bit<32> ip_tcp_flags_2;
    bit<32> ip_proto_0;
    bit<32> ip_proto_1;
    bit<32> ip_proto_2;
    bit<32> ip_src;
    bit<32> ip_dst;
    bit<32> ip_src_port_src;
    bit<32> ip_src_port_dst;
    bit<32> ip_dst_port_src;
    bit<32> ip_dst_port_dst;
    bit<32> ams_g_0;
    bit<32> ams_g_1;
    bit<32> ams_g_2;
}

header reg_meta_t {
    bit<32> hash_size;
    bit<32> current_reg;
    bit<32> current_index;
    bit<32> current_sketch_hash;
    bit<32> index_remaining;
    bit<1> cm_ip_cnt;
    bit<1> cm_ip_len;
    bit<1> cm_ip_port_dst_cnt;
    bit<1> cm_ip_port_dst_len;
    bit<1> cm_ip_tcp_flags_cnt;
    bit<1> cm_ip_tcp_flags_len;
    bit<1> cm_ip_proto_cnt;
    bit<1> cm_ip_proto_len;
    bit<1> bm_ip_src;
    bit<1> bm_ip_dst;
    bit<1> bm_ip_src_port_src;
    bit<1> bm_ip_src_port_dst;
    bit<1> bm_ip_dst_port_src;
    bit<1> bm_ip_dst_port_dst;
    bit<1> ams;
    bit<1> mv;
}

header epoch_meta_t {
    bit<1>  current_epoch;
    bit<1>  index_epoch;
    bit<32> sketch_temp;
    bit<6>  padding;
}

header cm_ip_cnt_meta_t {
    bit<32> sketch_0;
    bit<32> sketch_1;
    bit<32> sketch_2;
    bit<32> sketch_final;
    bit<32> sketch_temp;
}

header cm_ip_len_meta_t {
    bit<32> sketch_0;
    bit<32> sketch_1;
    bit<32> sketch_2;
    bit<32> sketch_final;
    bit<32> sketch_temp;
}

header cm_ip_port_dst_cnt_meta_t {
    bit<32> sketch_0;
    bit<32> sketch_1;
    bit<32> sketch_2;
    bit<32> sketch_final;
    bit<32> sketch_temp;
}

header cm_ip_port_dst_len_meta_t {
    bit<32> sketch_0;
    bit<32> sketch_1;
    bit<32> sketch_2;
    bit<32> sketch_final;
    bit<32> sketch_temp;
}

header cm_ip_tcp_flags_cnt_meta_t {
    bit<32> sketch_0;
    bit<32> sketch_1;
    bit<32> sketch_2;
    bit<32> sketch_final;
    bit<32> sketch_temp;
}

header cm_ip_tcp_flags_len_meta_t {
    bit<32> sketch_0;
    bit<32> sketch_1;
    bit<32> sketch_2;
    bit<32> sketch_final;
    bit<32> sketch_temp;
}

header cm_ip_proto_cnt_meta_t {
    bit<32> sketch_0;
    bit<32> sketch_1;
    bit<32> sketch_2;
    bit<32> sketch_final;
    bit<32> sketch_temp;
}

header cm_ip_proto_len_meta_t {
    bit<32> sketch_0;
    bit<32> sketch_1;
    bit<32> sketch_2;
    bit<32> sketch_final;
    bit<32> sketch_temp;
}

header bm_ip_src_meta_t {
    bit<32> sketch_0;
    bit<32> sketch_1;
}

header bm_ip_dst_meta_t {
    bit<32> sketch_0;
    bit<32> sketch_1;
}

header bm_ip_src_port_src_meta_t {
    bit<32> sketch_0;
    bit<32> sketch_1;
}

header bm_ip_src_port_dst_meta_t {
    bit<32> sketch_0;
    bit<32> sketch_1;
}

header bm_ip_dst_port_src_meta_t {
    bit<32> sketch_0;
    bit<32> sketch_1;
}

header bm_ip_dst_port_dst_meta_t {
    bit<32> sketch_0;
    bit<32> sketch_1;
}

header ams_meta_t {
    bit<32> sum_0;
    bit<32> sum_1;
    bit<32> sum_2;
    bit<32> sketch_final;
}

header mv_meta_t {
    bit<64> key_temp;
    bit<32> count_temp;
    bit<32> sum_temp;
    bit<32> sketch_temp;
}

header threshold_meta_t {
    bit<32> hash_flow;
    bit<32> flow_traffic;
    bit<32> flow_global_traffic;
    bit<32> global_traffic;
    bit<48> flow_ts;
}

struct metadata_t {
    meta_t 	                    meta;
    hash_meta_t                 hash;
    reg_meta_t	                reg;
    epoch_meta_t                epoch;
    cm_ip_cnt_meta_t	        cm_ip_cnt;
    cm_ip_len_meta_t	        cm_ip_len;
    cm_ip_port_dst_cnt_meta_t   cm_ip_port_dst_cnt;
    cm_ip_port_dst_len_meta_t   cm_ip_port_dst_len;
    cm_ip_tcp_flags_cnt_meta_t  cm_ip_tcp_flags_cnt;
    cm_ip_tcp_flags_len_meta_t  cm_ip_tcp_flags_len;
    cm_ip_proto_cnt_meta_t      cm_ip_proto_cnt;
    cm_ip_proto_len_meta_t      cm_ip_proto_len;
    bm_ip_src_meta_t            bm_ip_src;
    bm_ip_dst_meta_t 	        bm_ip_dst;
    bm_ip_src_port_src_meta_t 	bm_ip_src_port_src;
    bm_ip_src_port_dst_meta_t 	bm_ip_src_port_dst;
    bm_ip_dst_port_src_meta_t 	bm_ip_dst_port_src;
    bm_ip_dst_port_dst_meta_t 	bm_ip_dst_port_dst;
    ams_meta_t		            ams;
    mv_meta_t 	                mv;
    threshold_meta_t            threshold;
}

struct headers_t {
    ethernet_t	        ethernet;
    ipv4_t		        ipv4;
    tcp_t		        tcp;
    udp_t		        udp;
    icmp_t 		        icmp;
    packet_out_header_t packet_out;
    packet_in_header_t  packet_in;
}