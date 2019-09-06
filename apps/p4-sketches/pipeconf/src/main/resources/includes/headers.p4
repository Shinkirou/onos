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

header my_metadata_header {
    bit<16> l4_src_port;
    bit<16> l4_dst_port;
    bit<32> ping_hash;
}

header meta_cm_header {
    bit<32> cm_hash_0;
    bit<32> cm_hash_1;
    bit<32> cm_hash_2;
    bit<32> cm_sketch_0;
    bit<32> cm_sketch_1;
    bit<32> cm_sketch_2;
    bit<32> cm_sketch_final;
}

header meta_bm_header {
    bit<32> bm_hash_0;
    bit<32> bm_hash_1;
    bit<32> bm_hash_2;
    bit<32> bm_sketch_0;
    bit<32> bm_sketch_1;
    bit<32> bm_sketch_2;
} 

header meta_k_ary_header {
    bit<32> k_ary_hash_0;
    bit<32> k_ary_hash_1;
    bit<32> k_ary_hash_2;
    bit<32> k_ary_hash_3;
    bit<32> k_ary_hash_4;
    bit<32> k_ary_sketch_0;
    bit<32> k_ary_sketch_1;
    bit<32> k_ary_sketch_2;
    bit<32> k_ary_sketch_3;
    bit<32> k_ary_sketch_4;
    bit<32> k_ary_sketch_F2_0;
    bit<32> k_ary_sketch_F2_1;
    bit<32> k_ary_sketch_F2_2;
    bit<32> k_ary_sketch_F2_3;
    bit<32> k_ary_sketch_F2_4;
    bit<32> k_ary_estimate_F2;
    bit<32> k_ary_sum;
    bit<32> k_ary_final;
    bit<32> k_ary_alert;
} 

struct metadata_t {
    my_metadata_header      my_metadata;
    meta_cm_header          meta_cm;
    meta_bm_header          meta_bm;
    meta_k_ary_header       meta_k_ary;  
}