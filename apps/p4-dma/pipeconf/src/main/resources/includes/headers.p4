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
    bit<32> cm_ip_src_ip_dst;
    bit<32> cm_ip_dst_port_21;
    bit<32> cm_ip_dst_port_22;
    bit<32> cm_ip_dst_port_80;
    bit<32> cm_ip_dst_tcp_syn;
    bit<32> cm_ip_dst_icmp;
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
    bit<16> l4_src_port;
    bit<16> l4_dst_port;
}

header reg_meta_t {
    // Number of active virtual registers, related to the current active sketches and their required registers.
    bit<32> virtual_register_num;
    bit<32> hash_size;
    bit<32> current_register;
    bit<32> current_index;
    bit<32> current_sketch_hash;
    bit<32> index_remaining;
    bit<32> cm_ip_src_ip_dst;
    bit<32> cm_ip_dst_port_dst;
    bit<32> cm_ip_dst_tcp_flags;
    bit<32> cm_ip_dst_proto;
    bit<32> bm_ip_src;
    bit<32> bm_ip_dst;
    bit<32> bm_ip_src_port_src;
    bit<32> bm_ip_src_port_dst;
    bit<32> bm_ip_dst_port_src;
    bit<32> bm_ip_dst_port_dst;
    bit<32> ams;
    bit<32> mv;
    bit<32> sketches;
    // bit <4> padding;
}

header epoch_meta_t {
    bit<1>  current_epoch;
    bit<1>  index_epoch;
    bit<32> sketch_temp;
    bit<6>  padding;
}

header cm_ip_src_ip_dst_meta_t {
    bit<32> hash_0;
    bit<32> hash_1;
    bit<32> hash_2;
    bit<32> sketch_0;
    bit<32> sketch_1;
    bit<32> sketch_2;
    bit<32> sketch_final;
    bit<32> sketch_temp;
}

header cm_ip_dst_port_dst_meta_t {
    bit<32> hash_0;
    bit<32> hash_1;
    bit<32> hash_2;
    bit<32> sketch_0;
    bit<32> sketch_1;
    bit<32> sketch_2;
    bit<32> sketch_final;
    bit<32> sketch_temp;
}

header cm_ip_dst_tcp_flags_meta_t {
    bit<32> hash_0;
    bit<32> hash_1;
    bit<32> hash_2;
    bit<32> sketch_0;
    bit<32> sketch_1;
    bit<32> sketch_2;
    bit<32> sketch_final;
    bit<32> sketch_temp;
}

header cm_ip_dst_proto_meta_t {
    bit<32> hash_0;
    bit<32> hash_1;
    bit<32> hash_2;
    bit<32> sketch_0;
    bit<32> sketch_1;
    bit<32> sketch_2;
    bit<32> sketch_final;
    bit<32> sketch_temp;
}

header bm_ip_src_meta_t {
    bit<32> hash_0;
    bit<32> hash_1;
    bit<32> sketch_0;
    bit<32> sketch_1;
}

header bm_ip_dst_meta_t {
    bit<32> hash_0;
    bit<32> hash_1;
    bit<32> sketch_0;
    bit<32> sketch_1;
}

header bm_ip_src_port_src_meta_t {
    bit<32> hash_0;
    bit<32> hash_1;
    bit<32> sketch_0;
    bit<32> sketch_1;
}

header bm_ip_src_port_dst_meta_t {
    bit<32> hash_0;
    bit<32> hash_1;
    bit<32> sketch_0;
    bit<32> sketch_1;
}

header bm_ip_dst_port_src_meta_t {
    bit<32> hash_0;
    bit<32> hash_1;
    bit<32> sketch_0;
    bit<32> sketch_1;
}

header bm_ip_dst_port_dst_meta_t {
    bit<32> hash_0;
    bit<32> hash_1;
    bit<32> sketch_0;
    bit<32> sketch_1;
}

header ams_meta_t {
    bit<32> hash_0;
    bit<32> hash_1;
    bit<32> hash_2;
    bit<32> hash_g_0;
    bit<32> hash_g_1;
    bit<32> hash_g_2;
    bit<32> sum_0;
    bit<32> sum_1;
    bit<32> sum_2;
    bit<32> sketch_final;
}

header mv_meta_t {
    bit<32> hash_mv_0;
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
    bit<48> flow_time;

}

struct metadata_t {
    meta_t 	                meta;
    reg_meta_t	                reg;
    epoch_meta_t                epoch;
    cm_ip_src_ip_dst_meta_t	cm_ip_src_ip_dst;
    cm_ip_dst_port_dst_meta_t   cm_ip_dst_port_dst;
    cm_ip_dst_tcp_flags_meta_t  cm_ip_dst_tcp_flags;
    cm_ip_dst_proto_meta_t      cm_ip_dst_proto;
    bm_ip_src_meta_t            bm_ip_src;
    bm_ip_dst_meta_t 	        bm_ip_dst;
    bm_ip_src_port_src_meta_t 	bm_ip_src_port_src;
    bm_ip_src_port_dst_meta_t 	bm_ip_src_port_dst;
    bm_ip_dst_port_src_meta_t 	bm_ip_dst_port_src;
    bm_ip_dst_port_dst_meta_t 	bm_ip_dst_port_dst;
    ams_meta_t		        ams;
    mv_meta_t 	                mv;
    threshold_meta_t            threshold;
}

struct headers_t {
    ethernet_t	        ethernet;
    ipv4_t		ipv4;
    tcp_t		tcp;
    udp_t		udp;
    icmp_t 		icmp;
    packet_out_header_t packet_out;
    packet_in_header_t  packet_in;
}