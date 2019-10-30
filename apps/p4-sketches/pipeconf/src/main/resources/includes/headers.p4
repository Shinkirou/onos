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

// Packet-in header. Prepended to packets sent to the controller and used to
// carry the original ingress port where the packet was received.
@controller_header("packet_in")
header packet_in_header_t {
    bit<9> ingress_port;
    bit<7> _padding;
}

// Packet-out header. Prepended to packets received by the controller and used
// to tell the switch on which port this packet should be forwarded.
@controller_header("packet_out")
header packet_out_header_t {
    bit<9> egress_port;
    bit<7> _padding;
}

struct headers_t {
    ethernet_t ethernet;
    ipv4_t ipv4;
    tcp_t tcp;
    udp_t udp;
    packet_out_header_t packet_out;
    packet_in_header_t packet_in;
}

header meta_t {
    bit<16> l4_src_port;
    bit<16> l4_dst_port;
    bit<32> ping_hash;
}

header cm_meta_t {
    bit<32> cm_0_hash;
    bit<32> cm_1_hash;
    bit<32> cm_2_hash;
    bit<32> cm_0_sketch;
    bit<32> cm_1_sketch;
    bit<32> cm_2_sketch;
    bit<32> cm_final_sketch;
}

header bm_meta_t {
    bit<32> bm_0_hash;
    bit<32> bm_1_hash;
    bit<32> bm_2_hash;
    bit<32> bm_0_sketch;
    bit<32> bm_1_sketch;
    bit<32> bm_2_sketch;
}

header k_ary_meta_t {
    bit<32> t_interval;
    bit<32> k_ary_sum;
    bit<32> k_ary_median;
    bit<32> k_ary_0_hash;
    bit<32> k_ary_1_hash;
    bit<32> k_ary_2_hash;
    bit<32> k_ary_3_hash;
    bit<32> k_ary_4_hash;
    bit<32> k_ary_0_sketch;
    bit<32> k_ary_1_sketch;
    bit<32> k_ary_2_sketch;
    bit<32> k_ary_3_sketch;
    bit<32> k_ary_4_sketch;
    bit<32> k_ary_0_sketch_old;
    bit<32> k_ary_1_sketch_old;
    bit<32> k_ary_2_sketch_old;
    bit<32> k_ary_3_sketch_old;
    bit<32> k_ary_4_sketch_old;    
    bit<32> k_ary_0_forecast;
    bit<32> k_ary_1_forecast;
    bit<32> k_ary_2_forecast;
    bit<32> k_ary_3_forecast;
    bit<32> k_ary_4_forecast;
    bit<32> k_ary_0_error_sketch;
    bit<32> k_ary_1_error_sketch;
    bit<32> k_ary_2_error_sketch;
    bit<32> k_ary_3_error_sketch;
    bit<32> k_ary_4_error_sketch;
    bit<32> k_ary_0_est_row;
    bit<32> k_ary_1_est_row;
    bit<32> k_ary_2_est_row;
    bit<32> k_ary_3_est_row;
    bit<32> k_ary_4_est_row;
    bit<32> k_ary_0_est_F2_sum;
    bit<32> k_ary_1_est_F2_sum;
    bit<32> k_ary_2_est_F2_sum;
    bit<32> k_ary_3_est_F2_sum;
    bit<32> k_ary_4_est_F2_sum;    
}

struct metadata_t {
    meta_t          meta;
    cm_meta_t       cm_meta;
    bm_meta_t       bm_meta;
    k_ary_meta_t    k_ary_meta;
}
