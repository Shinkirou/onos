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

header meta_header {
    bit<16> l4_src_port;
    bit<16> l4_dst_port;
    bit<32> ping_hash;
}

header meta_cm_header {
    bit<32> hash_0;
    bit<32> hash_1;
    bit<32> hash_2;
    bit<32> sketch_0;
    bit<32> sketch_1;
    bit<32> sketch_2;
    bit<32> sketch_final;
}

header meta_bm_header {
    bit<32> hash_0;
    bit<32> hash_1;
    bit<32> hash_2;
    bit<32> sketch_0;
    bit<32> sketch_1;
    bit<32> sketch_2;
} 

header meta_k_ary_header {
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
    bit<32> est_F2_row_0;
    bit<32> est_F2_row_1;
    bit<32> est_F2_row_2;
    bit<32> est_F2_row_3;
    bit<32> est_F2_row_4; 
    bit<32> median;
    bit<32> estimate;   
    bit<32> estimate_F2;
    bit<32> sum;
    bit<32> final;
    bit<32> alert;
} 

struct metadata_t {
    meta_header             meta;
    meta_cm_header          meta_cm;
    meta_bm_header          meta_bm;
    meta_k_ary_header       meta_k_ary;  
}