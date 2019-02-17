
#include <core.p4>
#include <v1model.p4>

#define MAX_PORTS 255

const bit<8> IP_PROTO_UDP = 17;
const bit<8> IP_PROTO_TCP = 6;

const bit<32> THRESHOLD = 10;

const bit<16> ETH_TYPE_IPV4 = 0x800;
const bit<32> MAX_INT = 0xFFFFFFFF;

typedef bit<9> port_t;
const port_t CPU_PORT = 255;

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
}

// Packet-out header. Prepended to packets received by the controller and used
// to tell the switch on which port this packet should be forwarded.
@controller_header("packet_out")
header packet_out_header_t {
    bit<9> egress_port;
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
    bit<32> ping_hash_val;
}

header meta_count_min_header {
    bit<32> count_min_hash_val0;
    bit<32> count_min_hash_val1;
    bit<32> count_min_hash_val2;
    bit<32> count_min_val0;
    bit<32> count_min_val1;
    bit<32> count_min_val2;
    bit<32> count_min_val;
    bit<32> count_min_hash;
}

header meta_bitmap_header {
    bit<32> bitmap_hash_val0;
    bit<32> bitmap_hash_val1;
    bit<32> bitmap_hash_val2;
    bit<32> bitmap_val0;
    bit<32> bitmap_val1;
    bit<32> bitmap_val2;
} 

header meta_k_ary_header {
    bit<32> k_ary_hash_val0;
    bit<32> k_ary_hash_val1;
    bit<32> k_ary_hash_val2;
    bit<32> k_ary_hash_val3;
    bit<32> k_ary_hash_val4;
    bit<32> k_ary_val0;
    bit<32> k_ary_val1;
    bit<32> k_ary_val2;
    bit<32> k_ary_val3;
    bit<32> k_ary_val4;
    bit<32> k_ary_val_F2_0;
    bit<32> k_ary_val_F2_1;
    bit<32> k_ary_val_F2_2;
    bit<32> k_ary_val_F2_3;
    bit<32> k_ary_val_F2_4;
    bit<32> k_ary_estimate;
    bit<32> k_ary_estimate_old;
    bit<32> k_ary_estimate_F2;
    bit<32> k_ary_sum;
    bit<32> k_ary_threshold;
    bit<32> k_ary_final;
    bit<32> k_ary_alert;
} 

struct metadata_t {
    my_metadata_header      my_metadata;
    meta_count_min_header   meta_count_min;
    meta_bitmap_header      meta_bitmap;
    meta_k_ary_header       meta_k_ary;  
}

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
            IP_PROTO_TCP: parse_tcp;
            IP_PROTO_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        meta.my_metadata.l4_src_port = hdr.tcp.src_port;
        meta.my_metadata.l4_dst_port = hdr.tcp.dst_port;
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        meta.my_metadata.l4_src_port = hdr.udp.src_port;
        meta.my_metadata.l4_dst_port = hdr.udp.dst_port;
        transition accept;
    }
}

//------------------------------------------------------------------------------
// INGRESS PIPELINE
//------------------------------------------------------------------------------

control c_ingress(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

    register<bit<32>>(131072) count_min_register0;
    register<bit<32>>(131072) count_min_register1;  
    register<bit<32>>(131072) count_min_register2;  
    register<bit<32>>(131072) count_register_final;
    
    register<bit<32>>(131072) bitmap_register0;
    // Bitmap register for the source address.
    register<bit<32>>(131072) bitmap_register1;
    // Bitmap register for the destination address.
    register<bit<32>>(131072) bitmap_register2;

    register<bit<32>>(131072) k_ary_register0;
    register<bit<32>>(131072) k_ary_register1;
    register<bit<32>>(131072) k_ary_register2;
    register<bit<32>>(131072) k_ary_register3;
    register<bit<32>>(131072) k_ary_register4;
    register<bit<32>>(7)      k_ary_register_estimate_F2;

    bit<32> count_min_hash0;
    bit<32> count_min_hash1;
    bit<32> count_min_hash2;

    bit<32> bitmap_hash0;
    // Bitmap hash for the source address.
    bit<32> bitmap_hash1;
    // Bitmap hash for the destination address.
    bit<32> bitmap_hash2;

    bit<32> k_ary_hash0;
    bit<32> k_ary_hash1;
    bit<32> k_ary_hash2;
    bit<32> k_ary_hash3;
    bit<32> k_ary_hash4;

    bit<32> ping_hash;

    // We use these counters to count packets/bytes received/sent on each port.
    // For each counter we instantiate a number of cells equal to MAX_PORTS.
    // counter(MAX_PORTS, CounterType.packets_and_bytes) tx_port_counter;
    // counter(MAX_PORTS, CounterType.packets_and_bytes) rx_port_counter;

    action send_to_cpu() {
        // Packets sent to the controller needs to be prepended with the
        // packet-in header. By setting it valid we make sure it will be
        // deparsed on the wire (see c_deparser).
        standard_metadata.egress_spec = CPU_PORT;
        hdr.packet_in.setValid();
        hdr.packet_in.ingress_port = standard_metadata.ingress_port;
    }

    action set_out_port(port_t port) {
        // Specifies the output port for this packet by setting the
        // corresponding metadata.
        standard_metadata.egress_spec = port;
    }

    action _drop() {}

    // Count-min sketch actions

    action action_get_count_min_hash_0_val() {
        hash(count_min_hash0, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.my_metadata.l4_src_port, (bit<32>)meta.my_metadata.l4_dst_port}, 
            (bit<32>)131072);
        meta.meta_count_min.count_min_hash_val0 = count_min_hash0;
    }

    action action_get_count_min_hash_1_val() {
        hash(count_min_hash1, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.my_metadata.l4_src_port, (bit<32>)meta.my_metadata.l4_dst_port}, 
            (bit<32>)131072);
        meta.meta_count_min.count_min_hash_val1 = count_min_hash1;
    }

    action action_get_count_min_hash_2_val() {
        hash(count_min_hash2, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.my_metadata.l4_src_port, (bit<32>)meta.my_metadata.l4_dst_port},
            (bit<32>)131072);
        meta.meta_count_min.count_min_hash_val2 = count_min_hash2;
    }      

    action action_count_min_sketch_incr() {
        
        bit<32> tmp0;
        bit<32> tmp1;
        bit<32> tmp2;

        count_min_register0.read(tmp0, (bit<32>)meta.meta_count_min.count_min_hash_val0);
        count_min_register1.read(tmp1, (bit<32>)meta.meta_count_min.count_min_hash_val1);
        count_min_register2.read(tmp2, (bit<32>)meta.meta_count_min.count_min_hash_val2);

        meta.meta_count_min.count_min_val0 = tmp0;
        meta.meta_count_min.count_min_val1 = tmp1;
        meta.meta_count_min.count_min_val2 = tmp2;

        meta.meta_count_min.count_min_val0 = meta.meta_count_min.count_min_val0 + 1;
        meta.meta_count_min.count_min_val1 = meta.meta_count_min.count_min_val1 + 1;
        meta.meta_count_min.count_min_val2 = meta.meta_count_min.count_min_val2 + 1;

        count_min_register0.write((bit<32>)meta.meta_count_min.count_min_hash_val0, meta.meta_count_min.count_min_val0);
        count_min_register1.write((bit<32>)meta.meta_count_min.count_min_hash_val1, meta.meta_count_min.count_min_val1);
        count_min_register2.write((bit<32>)meta.meta_count_min.count_min_hash_val2, meta.meta_count_min.count_min_val2);
    }

    action action_count_min_register_write() {
        count_register_final.write((bit<32>)meta.meta_count_min.count_min_hash_val2, meta.meta_count_min.count_min_val);
    }

    // Bitmap sketch actions

    action action_bitmap_hash_0_val() {
        hash(bitmap_hash0,
            HashAlgorithm.crc32_custom,
            (bit<32>)0,
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.my_metadata.l4_src_port, (bit<32>)meta.my_metadata.l4_dst_port},
            (bit<32>)131072);
        meta.meta_bitmap.bitmap_hash_val0 = bitmap_hash0;
    }

    action action_bitmap_hash_1_val() {
        hash(bitmap_hash1, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.my_metadata.l4_src_port}, 
            (bit<32>)131072);
        meta.meta_bitmap.bitmap_hash_val1 = bitmap_hash1;
    }

    action action_bitmap_hash_2_val() {
        hash(bitmap_hash2, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.my_metadata.l4_dst_port}, 
            (bit<32>)131072);
        meta.meta_bitmap.bitmap_hash_val2 = bitmap_hash2;
    }          

    action action_bitmap_check_pair() {

        bit<32> tmp0;

        // Check the bitmap value for the (ip src, ip dst) pair
        bitmap_register0.read(tmp0, (bit<32>)meta.meta_bitmap.bitmap_hash_val0);
        meta.meta_bitmap.bitmap_val0 = tmp0;
    }

    action action_bitmap_new_pair() {

        bit<32> tmp1;
        bit<32> tmp2;

        meta.meta_bitmap.bitmap_val0 = meta.meta_bitmap.bitmap_val0 + 1;
        
        bitmap_register1.read(tmp1, (bit<32>)meta.meta_bitmap.bitmap_hash_val1);
        bitmap_register2.read(tmp2, (bit<32>)meta.meta_bitmap.bitmap_hash_val2);

        meta.meta_bitmap.bitmap_val1 = tmp1;
        meta.meta_bitmap.bitmap_val2 = tmp2;

        meta.meta_bitmap.bitmap_val1 = meta.meta_bitmap.bitmap_val1 + 1;
        meta.meta_bitmap.bitmap_val2 = meta.meta_bitmap.bitmap_val2 + 1;

        bitmap_register0.write((bit<32>)meta.meta_bitmap.bitmap_hash_val0, meta.meta_bitmap.bitmap_val0);
        bitmap_register1.write((bit<32>)meta.meta_bitmap.bitmap_hash_val1, meta.meta_bitmap.bitmap_val1);
        bitmap_register2.write((bit<32>)meta.meta_bitmap.bitmap_hash_val2, meta.meta_bitmap.bitmap_val2);
    }

    action action_bitmap_existing_pair() {     

        bit<32> tmp1;
        bit<32> tmp2;

        bitmap_register1.read(tmp1, (bit<32>)meta.meta_bitmap.bitmap_hash_val1);
        meta.meta_bitmap.bitmap_val1 = tmp1;

        bitmap_register2.read(tmp2, (bit<32>)meta.meta_bitmap.bitmap_hash_val2);
        meta.meta_bitmap.bitmap_val2 = tmp2;        
    }    

    // K-ary sketch actions

    action action_get_k_ary_hash_0_val() {
        hash(k_ary_hash0, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.my_metadata.l4_src_port, (bit<32>)meta.my_metadata.l4_dst_port}, 
            (bit<32>)131072);
        meta.meta_k_ary.k_ary_hash_val0 = k_ary_hash0;
    }

    action action_get_k_ary_hash_1_val() {
        hash(k_ary_hash1, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.my_metadata.l4_src_port, (bit<32>)meta.my_metadata.l4_dst_port}, 
            (bit<32>)131072);
        meta.meta_k_ary.k_ary_hash_val1 = k_ary_hash1;
    }

    action action_get_k_ary_hash_2_val() {
        hash(k_ary_hash2, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.my_metadata.l4_src_port, (bit<32>)meta.my_metadata.l4_dst_port}, 
            (bit<32>)131072);
        meta.meta_k_ary.k_ary_hash_val2 = k_ary_hash2;
    }

    action action_get_k_ary_hash_3_val() {
        hash(k_ary_hash3, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.my_metadata.l4_src_port, (bit<32>)meta.my_metadata.l4_dst_port}, 
            (bit<32>)131072);
        meta.meta_k_ary.k_ary_hash_val3 = k_ary_hash3;
    }

    action action_get_k_ary_hash_4_val() {
        hash(k_ary_hash4, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.my_metadata.l4_src_port, (bit<32>)meta.my_metadata.l4_dst_port}, 
            (bit<32>)131072);
        meta.meta_k_ary.k_ary_hash_val4 = k_ary_hash4;
    }

    action action_k_ary_sketch_incr() {
        
        bit<32> tmp0;
        bit<32> tmp1;
        bit<32> tmp2;
        bit<32> tmp3;
        bit<32> tmp4;
        bit<32> tmp5;

        bit<32> tmp6;
        bit<32> tmp7;
        bit<32> tmp8;
        bit<32> tmp9;
        bit<32> tmp10;

        // Retrieve the current sketch values.
        k_ary_register0.read(tmp0, (bit<32>)meta.meta_k_ary.k_ary_hash_val0);
        k_ary_register1.read(tmp1, (bit<32>)meta.meta_k_ary.k_ary_hash_val1);
        k_ary_register2.read(tmp2, (bit<32>)meta.meta_k_ary.k_ary_hash_val2);
        k_ary_register3.read(tmp3, (bit<32>)meta.meta_k_ary.k_ary_hash_val3);
        k_ary_register4.read(tmp4, (bit<32>)meta.meta_k_ary.k_ary_hash_val4);

        // Retrieve the current sum of all values.
        k_ary_register_estimate_F2.read(tmp5, (bit<32>)6);

        // Retrieve the current values for F2.
        k_ary_register_estimate_F2.read(tmp6, (bit<32>)0);
        k_ary_register_estimate_F2.read(tmp7, (bit<32>)1); 
        k_ary_register_estimate_F2.read(tmp8, (bit<32>)2); 
        k_ary_register_estimate_F2.read(tmp9, (bit<32>)3); 
        k_ary_register_estimate_F2.read(tmp10, (bit<32>)4);        

        meta.meta_k_ary.k_ary_val0 = tmp0;
        meta.meta_k_ary.k_ary_val1 = tmp1;
        meta.meta_k_ary.k_ary_val2 = tmp2;
        meta.meta_k_ary.k_ary_val3 = tmp3;
        meta.meta_k_ary.k_ary_val4 = tmp4;

        meta.meta_k_ary.k_ary_sum  = tmp5;

        meta.meta_k_ary.k_ary_val_F2_0 = tmp6;
        meta.meta_k_ary.k_ary_val_F2_1 = tmp7;
        meta.meta_k_ary.k_ary_val_F2_2 = tmp8;
        meta.meta_k_ary.k_ary_val_F2_3 = tmp9;
        meta.meta_k_ary.k_ary_val_F2_4 = tmp10;
        
        // Increase the sketch values.

        meta.meta_k_ary.k_ary_val0 = meta.meta_k_ary.k_ary_val0 + 1;
        meta.meta_k_ary.k_ary_val1 = meta.meta_k_ary.k_ary_val1 + 1;
        meta.meta_k_ary.k_ary_val2 = meta.meta_k_ary.k_ary_val2 + 1;
        meta.meta_k_ary.k_ary_val3 = meta.meta_k_ary.k_ary_val3 + 1;
        meta.meta_k_ary.k_ary_val4 = meta.meta_k_ary.k_ary_val4 + 1;

        // Increase the sum of all values.

        meta.meta_k_ary.k_ary_sum = meta.meta_k_ary.k_ary_sum + 5;

        // Increase the F2 auxiliary values for each row.

        if (meta.meta_k_ary.k_ary_val_F2_0 == 0) {
            meta.meta_k_ary.k_ary_val_F2_0 = meta.meta_k_ary.k_ary_val0 * meta.meta_k_ary.k_ary_val0;
        } else {
            meta.meta_k_ary.k_ary_val_F2_0 = meta.meta_k_ary.k_ary_val_F2_0 - ((meta.meta_k_ary.k_ary_val0 - 1) * (meta.meta_k_ary.k_ary_val0 - 1));
            meta.meta_k_ary.k_ary_val_F2_0 = meta.meta_k_ary.k_ary_val_F2_0 + (meta.meta_k_ary.k_ary_val0 * meta.meta_k_ary.k_ary_val0);
        }
        if (meta.meta_k_ary.k_ary_val_F2_1 == 0) {
            meta.meta_k_ary.k_ary_val_F2_1 = meta.meta_k_ary.k_ary_val1 * meta.meta_k_ary.k_ary_val1;
        } else {
            meta.meta_k_ary.k_ary_val_F2_1 = meta.meta_k_ary.k_ary_val_F2_1 - ((meta.meta_k_ary.k_ary_val1 - 1) * (meta.meta_k_ary.k_ary_val1 - 1));
            meta.meta_k_ary.k_ary_val_F2_1 = meta.meta_k_ary.k_ary_val_F2_1 + (meta.meta_k_ary.k_ary_val1 * meta.meta_k_ary.k_ary_val1);
        }
        if (meta.meta_k_ary.k_ary_val_F2_2 == 0) {
            meta.meta_k_ary.k_ary_val_F2_2 = meta.meta_k_ary.k_ary_val2 * meta.meta_k_ary.k_ary_val2;
        } else {
            meta.meta_k_ary.k_ary_val_F2_2 = meta.meta_k_ary.k_ary_val_F2_2 - ((meta.meta_k_ary.k_ary_val2 - 1) * (meta.meta_k_ary.k_ary_val2 - 1));
            meta.meta_k_ary.k_ary_val_F2_2 = meta.meta_k_ary.k_ary_val_F2_2 + (meta.meta_k_ary.k_ary_val2 * meta.meta_k_ary.k_ary_val2);
        }
        if (meta.meta_k_ary.k_ary_val_F2_3 == 0) {
            meta.meta_k_ary.k_ary_val_F2_3 = meta.meta_k_ary.k_ary_val3 * meta.meta_k_ary.k_ary_val3;
        } else {
            meta.meta_k_ary.k_ary_val_F2_3 = meta.meta_k_ary.k_ary_val_F2_3 - ((meta.meta_k_ary.k_ary_val3 - 1) * (meta.meta_k_ary.k_ary_val3 - 1));
            meta.meta_k_ary.k_ary_val_F2_3 = meta.meta_k_ary.k_ary_val_F2_3 + (meta.meta_k_ary.k_ary_val3 * meta.meta_k_ary.k_ary_val3);
        }
        if (meta.meta_k_ary.k_ary_val_F2_4 == 0) {
            meta.meta_k_ary.k_ary_val_F2_4 = meta.meta_k_ary.k_ary_val4 * meta.meta_k_ary.k_ary_val4;
        } else {
            meta.meta_k_ary.k_ary_val_F2_4 = meta.meta_k_ary.k_ary_val_F2_4 - ((meta.meta_k_ary.k_ary_val4 - 1) * (meta.meta_k_ary.k_ary_val4 - 1));
            meta.meta_k_ary.k_ary_val_F2_4 = meta.meta_k_ary.k_ary_val_F2_4 + (meta.meta_k_ary.k_ary_val4 * meta.meta_k_ary.k_ary_val4);
        }

        // Update the current sketch values.
        k_ary_register0.write((bit<32>)meta.meta_k_ary.k_ary_hash_val0, meta.meta_k_ary.k_ary_val0);
        k_ary_register1.write((bit<32>)meta.meta_k_ary.k_ary_hash_val1, meta.meta_k_ary.k_ary_val1);
        k_ary_register2.write((bit<32>)meta.meta_k_ary.k_ary_hash_val2, meta.meta_k_ary.k_ary_val2);
        k_ary_register3.write((bit<32>)meta.meta_k_ary.k_ary_hash_val3, meta.meta_k_ary.k_ary_val3);
        k_ary_register4.write((bit<32>)meta.meta_k_ary.k_ary_hash_val4, meta.meta_k_ary.k_ary_val4);

        // Update the current sum of all values.
        k_ary_register_estimate_F2.write((bit<32>)6, meta.meta_k_ary.k_ary_sum);

        // Update the F2 auxiliary values for each row.
        k_ary_register_estimate_F2.write((bit<32>)0, meta.meta_k_ary.k_ary_val_F2_0);
        k_ary_register_estimate_F2.write((bit<32>)1, meta.meta_k_ary.k_ary_val_F2_1); 
        k_ary_register_estimate_F2.write((bit<32>)2, meta.meta_k_ary.k_ary_val_F2_2); 
        k_ary_register_estimate_F2.write((bit<32>)3, meta.meta_k_ary.k_ary_val_F2_3); 
        k_ary_register_estimate_F2.write((bit<32>)4, meta.meta_k_ary.k_ary_val_F2_4);
    }

    /*
    action action_k_ary_sketch_estimate() {
        
        bit<32> tmp0;
        bit<32> tmp1;
        bit<32> tmp2;
        bit<32> tmp3;
        bit<32> tmp4;
        bit<32> tmp5;

        // Retrieve the current sketch values.
        k_ary_register0.read(tmp0, (bit<32>)meta.meta_k_ary.k_ary_hash_val0);
        k_ary_register1.read(tmp1, (bit<32>)meta.meta_k_ary.k_ary_hash_val1);
        k_ary_register2.read(tmp2, (bit<32>)meta.meta_k_ary.k_ary_hash_val2);
        k_ary_register3.read(tmp3, (bit<32>)meta.meta_k_ary.k_ary_hash_val3);
        k_ary_register4.read(tmp4, (bit<32>)meta.meta_k_ary.k_ary_hash_val4);

        // Retrieve the current sum of all values.
        k_ary_register_estimate_F2.read(tmp5, (bit<32>)6);

        meta.meta_k_ary.k_ary_val0 = tmp0;
        meta.meta_k_ary.k_ary_val1 = tmp1;
        meta.meta_k_ary.k_ary_val2 = tmp2;
        meta.meta_k_ary.k_ary_val3 = tmp3;
        meta.meta_k_ary.k_ary_val4 = tmp4;

        meta.meta_k_ary.k_ary_sum  = tmp5;

        // Calculate the estimate for each row.

        meta.meta_k_ary.k_ary_val0 = (meta.meta_k_ary.k_ary_val0 - (meta.meta_k_ary.k_ary_sum / 131072)) / (1 - (1/131072));               
        meta.meta_k_ary.k_ary_val1 = (meta.meta_k_ary.k_ary_val1 - (meta.meta_k_ary.k_ary_sum / 131072)) / (1 - (1/131072));
        meta.meta_k_ary.k_ary_val2 = (meta.meta_k_ary.k_ary_val2 - (meta.meta_k_ary.k_ary_sum / 131072)) / (1 - (1/131072));
        meta.meta_k_ary.k_ary_val3 = (meta.meta_k_ary.k_ary_val3 - (meta.meta_k_ary.k_ary_sum / 131072)) / (1 - (1/131072));
        meta.meta_k_ary.k_ary_val4 = (meta.meta_k_ary.k_ary_val4 - (meta.meta_k_ary.k_ary_sum / 131072)) / (1 - (1/131072));

        // Discover the median value

        tmp0 = meta.meta_k_ary.k_ary_val0;
        tmp1 = meta.meta_k_ary.k_ary_val1;
        tmp2 = meta.meta_k_ary.k_ary_val2;
        tmp3 = meta.meta_k_ary.k_ary_val3;
        tmp4 = meta.meta_k_ary.k_ary_val4;

        if  ((tmp0 <= tmp1 && tmp0 <= tmp2 && tmp0 >= tmp3 && tmp0 >= tmp4) ||
            (tmp0 <= tmp1 && tmp0 <= tmp3 && tmp0 >= tmp2 && tmp0 >= tmp4) ||
            (tmp0 <= tmp1 && tmp0 <= tmp4 && tmp0 >= tmp2 && tmp0 >= tmp3) ||
            (tmp0 <= tmp2 && tmp0 <= tmp3 && tmp0 >= tmp1 && tmp0 >= tmp4) ||
            (tmp0 <= tmp2 && tmp0 <= tmp4 && tmp0 >= tmp1 && tmp0 >= tmp3) ||
            (tmp0 <= tmp3 && tmp0 <= tmp4 && tmp0 >= tmp1 && tmp0 >= tmp2)) {
                meta.meta_k_ary.k_ary_estimate = tmp0;
        } 
        else if ((tmp1 <= tmp0 && tmp1 <= tmp2 && tmp1 >= tmp3 && tmp1 >= tmp4) ||
                (tmp1 <= tmp0 && tmp1 <= tmp3 && tmp1 >= tmp2 && tmp1 >= tmp4) ||
                (tmp1 <= tmp0 && tmp1 <= tmp4 && tmp1 >= tmp2 && tmp1 >= tmp3) ||
                (tmp1 <= tmp2 && tmp1 <= tmp3 && tmp1 >= tmp0 && tmp1 >= tmp4) ||
                (tmp1 <= tmp2 && tmp1 <= tmp4 && tmp1 >= tmp0 && tmp1 >= tmp3) ||
                (tmp1 <= tmp3 && tmp1 <= tmp4 && tmp1 >= tmp0 && tmp1 >= tmp2)) {
                    meta.meta_k_ary.k_ary_estimate = tmp1;
        }
        else if ((tmp2 <= tmp1 && tmp2 <= tmp0 && tmp2 >= tmp3 && tmp2 >= tmp4) ||
                (tmp2 <= tmp1 && tmp2 <= tmp3 && tmp2 >= tmp0 && tmp2 >= tmp4) ||
                (tmp2 <= tmp1 && tmp2 <= tmp4 && tmp2 >= tmp0 && tmp2 >= tmp3) ||
                (tmp2 <= tmp0 && tmp2 <= tmp3 && tmp2 >= tmp1 && tmp2 >= tmp4) ||
                (tmp2 <= tmp0 && tmp2 <= tmp4 && tmp2 >= tmp1 && tmp2 >= tmp3) ||
                (tmp2 <= tmp3 && tmp2 <= tmp4 && tmp2 >= tmp1 && tmp2 >= tmp0)) {
                    meta.meta_k_ary.k_ary_estimate = tmp2;
        }
        else if ((tmp3 <= tmp1 && tmp3 <= tmp2 && tmp3 >= tmp0 && tmp3 >= tmp4) ||
                (tmp3 <= tmp1 && tmp3 <= tmp0 && tmp3 >= tmp2 && tmp3 >= tmp4) ||
                (tmp3 <= tmp1 && tmp3 <= tmp4 && tmp3 >= tmp2 && tmp3 >= tmp0) ||
                (tmp3 <= tmp2 && tmp3 <= tmp0 && tmp3 >= tmp1 && tmp3 >= tmp4) ||
                (tmp3 <= tmp2 && tmp3 <= tmp4 && tmp3 >= tmp1 && tmp3 >= tmp0) ||
                (tmp3 <= tmp0 && tmp3 <= tmp4 && tmp3 >= tmp1 && tmp3 >= tmp2)) {
                    meta.meta_k_ary.k_ary_estimate = tmp3;
        }
        else {
                meta.meta_k_ary.k_ary_estimate = tmp4;
        }

        // Save the old value for threshold estimation.

        k_ary_register_estimate.read(tmp5, (bit<32>)meta.meta_k_ary.k_ary_hash_val0);
        meta.meta_k_ary.k_ary_estimate_old = tmp5;
        k_ary_register_estimate_old.write((bit<32>)meta.meta_k_ary.k_ary_hash_val0, meta.meta_k_ary.k_ary_estimate_old);

        // Write the new value to the register.
        k_ary_register_estimate.write((bit<32>)meta.meta_k_ary.k_ary_hash_val0, meta.meta_k_ary.k_ary_estimate);
    }
    */

    action action_k_ary_sketch_estimate_F2() {
        
        bit<32> tmp0;
        bit<32> tmp1;
        bit<32> tmp2;
        bit<32> tmp3;
        bit<32> tmp4;
        bit<32> tmp5;

        // Retrieve the F2 auxiliary values for each row.
        k_ary_register_estimate_F2.read(tmp0, (bit<32>)0);
        k_ary_register_estimate_F2.read(tmp1, (bit<32>)1);
        k_ary_register_estimate_F2.read(tmp2, (bit<32>)2);
        k_ary_register_estimate_F2.read(tmp3, (bit<32>)3);
        k_ary_register_estimate_F2.read(tmp4, (bit<32>)4);

        // Retrieve the current sum of all values.
        k_ary_register_estimate_F2.read(tmp5, (bit<32>)6);

        meta.meta_k_ary.k_ary_val_F2_0 = tmp0;
        meta.meta_k_ary.k_ary_val_F2_1 = tmp1;
        meta.meta_k_ary.k_ary_val_F2_2 = tmp2;
        meta.meta_k_ary.k_ary_val_F2_3 = tmp3;
        meta.meta_k_ary.k_ary_val_F2_4 = tmp4;

        meta.meta_k_ary.k_ary_sum  = tmp5;

        // Calculate the estimate F2 for each row.

        meta.meta_k_ary.k_ary_val_F2_0 = (131072 / (131072 - 1)) * (meta.meta_k_ary.k_ary_val_F2_0) - (1 / (131072 - 1)) * (meta.meta_k_ary.k_ary_sum * meta.meta_k_ary.k_ary_sum);
        meta.meta_k_ary.k_ary_val_F2_1 = (131072 / (131072 - 1)) * (meta.meta_k_ary.k_ary_val_F2_1) - (1 / (131072 - 1)) * (meta.meta_k_ary.k_ary_sum * meta.meta_k_ary.k_ary_sum);
        meta.meta_k_ary.k_ary_val_F2_2 = (131072 / (131072 - 1)) * (meta.meta_k_ary.k_ary_val_F2_2) - (1 / (131072 - 1)) * (meta.meta_k_ary.k_ary_sum * meta.meta_k_ary.k_ary_sum);
        meta.meta_k_ary.k_ary_val_F2_3 = (131072 / (131072 - 1)) * (meta.meta_k_ary.k_ary_val_F2_3) - (1 / (131072 - 1)) * (meta.meta_k_ary.k_ary_sum * meta.meta_k_ary.k_ary_sum);
        meta.meta_k_ary.k_ary_val_F2_4 = (131072 / (131072 - 1)) * (meta.meta_k_ary.k_ary_val_F2_4) - (1 / (131072 - 1)) * (meta.meta_k_ary.k_ary_sum * meta.meta_k_ary.k_ary_sum);      
    
        // Discover the median value

        tmp0 = meta.meta_k_ary.k_ary_val_F2_0;
        tmp1 = meta.meta_k_ary.k_ary_val_F2_1;
        tmp2 = meta.meta_k_ary.k_ary_val_F2_2;
        tmp3 = meta.meta_k_ary.k_ary_val_F2_3;
        tmp4 = meta.meta_k_ary.k_ary_val_F2_4;

        if  ((tmp0 <= tmp1 && tmp0 <= tmp2 && tmp0 >= tmp3 && tmp0 >= tmp4) ||
            (tmp0 <= tmp1 && tmp0 <= tmp3 && tmp0 >= tmp2 && tmp0 >= tmp4) ||
            (tmp0 <= tmp1 && tmp0 <= tmp4 && tmp0 >= tmp2 && tmp0 >= tmp3) ||
            (tmp0 <= tmp2 && tmp0 <= tmp3 && tmp0 >= tmp1 && tmp0 >= tmp4) ||
            (tmp0 <= tmp2 && tmp0 <= tmp4 && tmp0 >= tmp1 && tmp0 >= tmp3) ||
            (tmp0 <= tmp3 && tmp0 <= tmp4 && tmp0 >= tmp1 && tmp0 >= tmp2)) {
                meta.meta_k_ary.k_ary_estimate_F2 = tmp0;
        } 
        else if ((tmp1 <= tmp0 && tmp1 <= tmp2 && tmp1 >= tmp3 && tmp1 >= tmp4) ||
                (tmp1 <= tmp0 && tmp1 <= tmp3 && tmp1 >= tmp2 && tmp1 >= tmp4) ||
                (tmp1 <= tmp0 && tmp1 <= tmp4 && tmp1 >= tmp2 && tmp1 >= tmp3) ||
                (tmp1 <= tmp2 && tmp1 <= tmp3 && tmp1 >= tmp0 && tmp1 >= tmp4) ||
                (tmp1 <= tmp2 && tmp1 <= tmp4 && tmp1 >= tmp0 && tmp1 >= tmp3) ||
                (tmp1 <= tmp3 && tmp1 <= tmp4 && tmp1 >= tmp0 && tmp1 >= tmp2)) {
                    meta.meta_k_ary.k_ary_estimate_F2 = tmp1;
        }
        else if ((tmp2 <= tmp1 && tmp2 <= tmp0 && tmp2 >= tmp3 && tmp2 >= tmp4) ||
                (tmp2 <= tmp1 && tmp2 <= tmp3 && tmp2 >= tmp0 && tmp2 >= tmp4) ||
                (tmp2 <= tmp1 && tmp2 <= tmp4 && tmp2 >= tmp0 && tmp2 >= tmp3) ||
                (tmp2 <= tmp0 && tmp2 <= tmp3 && tmp2 >= tmp1 && tmp2 >= tmp4) ||
                (tmp2 <= tmp0 && tmp2 <= tmp4 && tmp2 >= tmp1 && tmp2 >= tmp3) ||
                (tmp2 <= tmp3 && tmp2 <= tmp4 && tmp2 >= tmp1 && tmp2 >= tmp0)) {
                    meta.meta_k_ary.k_ary_estimate_F2 = tmp2;
        }
        else if ((tmp3 <= tmp1 && tmp3 <= tmp2 && tmp3 >= tmp0 && tmp3 >= tmp4) ||
                (tmp3 <= tmp1 && tmp3 <= tmp0 && tmp3 >= tmp2 && tmp3 >= tmp4) ||
                (tmp3 <= tmp1 && tmp3 <= tmp4 && tmp3 >= tmp2 && tmp3 >= tmp0) ||
                (tmp3 <= tmp2 && tmp3 <= tmp0 && tmp3 >= tmp1 && tmp3 >= tmp4) ||
                (tmp3 <= tmp2 && tmp3 <= tmp4 && tmp3 >= tmp1 && tmp3 >= tmp0) ||
                (tmp3 <= tmp0 && tmp3 <= tmp4 && tmp3 >= tmp1 && tmp3 >= tmp2)) {
                    meta.meta_k_ary.k_ary_estimate_F2 = tmp3;
        }
        else {
                meta.meta_k_ary.k_ary_estimate_F2 = tmp4;
        }

        k_ary_register_estimate_F2.write((bit<32>)5, meta.meta_k_ary.k_ary_estimate_F2);
    }

    /*
    action action_k_ary_sketch_check_threshold() {

        meta.meta_k_ary.k_ary_final = meta.meta_k_ary.k_ary_estimate - meta.meta_k_ary.k_ary_estimate_old;

        meta.meta_k_ary.k_ary_threshold = THRESHOLD * (meta.meta_k_ary.k_ary_estimate_F2^(1/2));

        if (meta.meta_k_ary.k_ary_final > meta.meta_k_ary.k_ary_threshold) {
            meta.meta_k_ary.k_ary_alert = 1;
        } else {
            meta.meta_k_ary.k_ary_alert = 0;
        }

        k_ary_register_alert.write((bit<32>)meta.meta_k_ary.k_ary_hash_val0, meta.meta_k_ary.k_ary_alert);
    }
    */

    // Ping hash.

    action action_get_ping_hash_val() {
        hash(ping_hash, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr}, 
            (bit<32>)131072);
        meta.my_metadata.ping_hash_val = ping_hash;
    } 

    // Table counter used to count packets and bytes matched by each entry of
    // t_l2_fwd table.
    direct_counter(CounterType.packets_and_bytes) l2_fwd_counter;

    table t_l2_fwd {
        key = {
            standard_metadata.ingress_port  : ternary;
            hdr.ethernet.dst_addr           : ternary;
            hdr.ethernet.src_addr           : ternary;
            hdr.ethernet.ether_type         : ternary;
            hdr.ipv4.protocol               : ternary;
            hdr.ipv4.src_addr               : ternary;
            hdr.ipv4.dst_addr               : ternary;
            hdr.tcp.src_port                : ternary;
            hdr.tcp.dst_port                : ternary;
            hdr.udp.src_port                : ternary;
            hdr.udp.dst_port                : ternary;
        }
        actions = {
            set_out_port;
            send_to_cpu;
            _drop;
            NoAction;
        }
        default_action = NoAction();
        size = 524288;
        counters = l2_fwd_counter;
    }          

    // Defines the processing applied by this control block. You can see this as
    // the main function applied to every packet received by the switch.
    apply {
        if (standard_metadata.ingress_port == CPU_PORT) {
            // Packet received from CPU_PORT, this is a packet-out sent by the
            // controller. Skip table processing, set the egress port as
            // requested by the controller (packet_out header) and remove the
            // packet_out header.           
            standard_metadata.egress_spec = hdr.packet_out.egress_port;
            hdr.packet_out.setInvalid();
        } else {
            // Packet received from data plane port.
            // Applies table t_l2_fwd to the packet.
            if (t_l2_fwd.apply().hit) {
                
                // Count-min sketch

                action_get_count_min_hash_0_val();
                action_get_count_min_hash_1_val();
                action_get_count_min_hash_2_val();
                action_count_min_sketch_incr();                
                
                meta.meta_count_min.count_min_val = meta.meta_count_min.count_min_val0;
                meta.meta_count_min.count_min_hash = meta.meta_count_min.count_min_hash_val0;
                
                if (meta.meta_count_min.count_min_val > meta.meta_count_min.count_min_val1) {
                    meta.meta_count_min.count_min_val = meta.meta_count_min.count_min_val1;
                    meta.meta_count_min.count_min_hash = meta.meta_count_min.count_min_hash_val1;
                }
                
                if (meta.meta_count_min.count_min_val > meta.meta_count_min.count_min_val2) {
                    meta.meta_count_min.count_min_val = meta.meta_count_min.count_min_val2;
                    meta.meta_count_min.count_min_hash = meta.meta_count_min.count_min_hash_val2;
                }

                action_count_min_register_write();  
                
                // Bitmap sketch

                action_bitmap_hash_0_val();
                action_bitmap_hash_1_val();
                action_bitmap_hash_2_val();                
     
                // Check the bitmap value for the (ip src, ip dst) pair
                action_bitmap_check_pair();

                if (meta.meta_bitmap.bitmap_val0 == 0) {
                    // if the value is 0, we write the bitmap value on register0 and increase the counter
                    // for the ip src on register1 (meaning that we have a new pair)
                    action_bitmap_new_pair();
                } else {
                    // if the value is 1, we do nothing (the pair is already accounted for)
                    action_bitmap_existing_pair();
                }

                // K-ary sketch

                // Update

                action_get_k_ary_hash_0_val();
                action_get_k_ary_hash_1_val();
                action_get_k_ary_hash_2_val();
                action_get_k_ary_hash_3_val();
                action_get_k_ary_hash_4_val();

                action_k_ary_sketch_incr();

                // Check if the current packet part of a pingall.
                // Only run both estimates if true.

                action_get_ping_hash_val();

                if ((bit<32>)meta.my_metadata.ping_hash_val == (bit<32>)93017) {
                    // action_k_ary_sketch_estimate(); 
                    action_k_ary_sketch_estimate_F2();
                }

                // action_k_ary_sketch_check_threshold();

                // Packet hit an entry in t_l2_fwd table. A forwarding action
                // has already been taken. No need to apply other tables, exit
                // this control block.                
                return;
            }
        }
     }
}

//------------------------------------------------------------------------------
// EGRESS PIPELINE
//------------------------------------------------------------------------------

control c_egress(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {
    apply {}
}

//------------------------------------------------------------------------------
// CHECKSUM HANDLING
//------------------------------------------------------------------------------

control c_verify_checksum(inout headers_t hdr, inout metadata_t meta) {
    apply {}
}

control c_compute_checksum(inout headers_t hdr, inout metadata_t meta) {
    apply {}
}

//------------------------------------------------------------------------------
// DEPARSER
//------------------------------------------------------------------------------

control c_deparser(packet_out packet, in headers_t hdr) {
    apply {
        packet.emit(hdr.packet_in);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

//------------------------------------------------------------------------------
// SWITCH INSTANTIATION
//------------------------------------------------------------------------------

V1Switch(c_parser(), c_verify_checksum(), c_ingress(), c_egress(), c_compute_checksum(), c_deparser()) main;