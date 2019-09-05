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

// Metadata for the various univmon components.

header metadata_header {
    bit<16> l4_src_port;
    bit<16> l4_dst_port;
    bit<32> binary_hash_0;
    bit<32> binary_hash_1;
    bit<32> binary_hash_2;
    bit<32> binary_hash_3;
    bit<32> count_register_hash_0;
    bit<32> count_register_hash_1;
    bit<32> count_register_hash_2;
    bit<32> count_register_hash_3;
    bit<32> count_update_hash_0;
    bit<32> count_update_hash_1;
    bit<32> count_update_hash_2;
    bit<32> count_update_hash_3;
    bit<32> packet_counter_0;
    bit<32> packet_counter_1;
    bit<32> packet_counter_2;
    bit<32> packet_counter_3;
    bit<32> count_final_val;
    bit<32> top_k_stage_1_hash;
    bit<32> top_k_stage_2_hash;
    bit<32> top_k_stage_3_hash;
}

// Metadata header for the hashpipe space-saving algorithm.

header metadata_tracking_header {
    bit<32> mKeyInTable;
    bit<32> mCountInTable;
    bit<32> mIndex1;
    bit<32> mIndex2;
    bit<32> mIndex3;
    bit<1>  mValid;
    bit<32> mKeyCarried;
    bit<32> mCountCarried;
    bit<32> mSwapSpace;
    bit<7> _padding;
}

struct metadata_t {
    metadata_header             metadata_packet;
    metadata_tracking_header    metadata_tracking;
}
