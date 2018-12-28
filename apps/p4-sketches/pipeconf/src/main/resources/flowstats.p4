
#include <core.p4>
#include <v1model.p4>

#define MAX_PORTS 255

// #define IP_PROTO_TCP 8w6
// #define IP_PROTO_UDP 8w17

const bit<8> IP_PROTO_UDP = 17;
const bit<8> IP_PROTO_TCP = 6;

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
    bit<32> count_min_hash_val0;
    bit<32> count_min_hash_val1;
    bit<32> count_min_hash_val2;
    bit<32> count_min_val0;
    bit<32> count_min_val1;
    bit<32> count_min_val2;
    bit<32> count_min_val;
    bit<32> count_min_hash;
    bit<32> bitmap_hash_val0;
    bit<32> bitmap_hash_val1;
    bit<32> bitmap_val0;
    bit<32> bitmap_val1;
    // bit<32> ip_proto;
    bit<16> l4_src_port;
    bit<16> l4_dst_port;
}

struct metadata_t {
    my_metadata_header  my_metadata;
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

    register<bit<32>>(65536) count_min_register0;
    register<bit<32>>(65536) count_min_register1;  
    register<bit<32>>(65536) count_min_register2;  
    register<bit<32>>(65536) count_register_final;  

    register<bit<32>>(65536) bitmap_register0;
    register<bit<32>>(65536) bitmap_register1;

    register<bit<32>>(65536) kary_register0;
    register<bit<32>>(65536) kary_register1;
    register<bit<32>>(65536) kary_register2;

    bit<32> packet_count_min_hash0;
    bit<32> packet_count_min_hash1;
    bit<32> packet_count_min_hash2;

    bit<32> packet_bitmap_hash0;
    bit<32> packet_bitmap_hash1;


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

    action _drop() {
        mark_to_drop();
    }

    action action_get_count_min_hash_0_val() {
        hash(packet_count_min_hash0, 
            HashAlgorithm.crc32, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.ipv4.protocol, hdr.ethernet.src_addr}, 
            (bit<32>)65536);
        meta.my_metadata.count_min_hash_val0 = packet_count_min_hash0;
    }

    action action_get_count_min_hash_1_val() {
        hash(packet_count_min_hash1, 
            HashAlgorithm.crc32, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.ipv4.protocol, hdr.ethernet.dst_addr}, 
            (bit<32>)65536);
        meta.my_metadata.count_min_hash_val1 = packet_count_min_hash1;
    }  

    action action_get_count_min_hash_2_val() {
        hash(packet_count_min_hash2, 
            HashAlgorithm.crc32, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.my_metadata.l4_src_port, (bit<32>)meta.my_metadata.l4_dst_port},
            (bit<32>)65536);
        meta.my_metadata.count_min_hash_val2 = packet_count_min_hash2;
    }      

    action action_count_min_sketch_incr() {
        
        bit<32> tmp0;
        bit<32> tmp1;
        bit<32> tmp2;

        count_min_register0.read(tmp0, (bit<32>)meta.my_metadata.count_min_hash_val0);
        count_min_register1.read(tmp1, (bit<32>)meta.my_metadata.count_min_hash_val1);
        count_min_register2.read(tmp2, (bit<32>)meta.my_metadata.count_min_hash_val2);

        meta.my_metadata.count_min_val0 = tmp0;
        meta.my_metadata.count_min_val1 = tmp1;
        meta.my_metadata.count_min_val2 = tmp2;

        meta.my_metadata.count_min_val0 = meta.my_metadata.count_min_val0 + 1;
        meta.my_metadata.count_min_val1 = meta.my_metadata.count_min_val1 + 1;
        meta.my_metadata.count_min_val2 = meta.my_metadata.count_min_val2 + 1;

        count_min_register0.write((bit<32>)meta.my_metadata.count_min_hash_val0, meta.my_metadata.count_min_val0);
        count_min_register1.write((bit<32>)meta.my_metadata.count_min_hash_val1, meta.my_metadata.count_min_val1);
        count_min_register2.write((bit<32>)meta.my_metadata.count_min_hash_val2, meta.my_metadata.count_min_val2);
    }

    action action_count_min_register_write() {
        count_register_final.write((bit<32>)meta.my_metadata.count_min_hash_val2, meta.my_metadata.count_min_val);
    }

    action action_bitmap_hash_0_val() {
        hash(packet_bitmap_hash0,
            HashAlgorithm.crc32,
            (bit<32>)0,
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr},
            (bit<32>)65536);
        meta.my_metadata.bitmap_hash_val0 = packet_bitmap_hash0;
    }

    action action_bitmap_hash_1_val() {
        hash(packet_bitmap_hash1, 
            HashAlgorithm.crc32, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr}, 
            (bit<32>)65536);
        meta.my_metadata.bitmap_hash_val1 = packet_bitmap_hash1;
    }       

    action action_bitmap_check_pair() {     

        bit<32> tmp0;

        // Check the bitmap value for the (ip src, ip dst) pair
        bitmap_register0.read(tmp0, (bit<32>)meta.my_metadata.bitmap_hash_val0);
        meta.my_metadata.bitmap_val0 = tmp0;
    }

    action action_bitmap_new_pair() {     
        
        bit<32> tmp1;

        meta.my_metadata.bitmap_val0 = meta.my_metadata.bitmap_val0 + 1;
        bitmap_register1.read(tmp1, (bit<32>)meta.my_metadata.bitmap_hash_val1);

        meta.my_metadata.bitmap_val1 = tmp1;
        meta.my_metadata.bitmap_val1 = meta.my_metadata.bitmap_val1 + 1;
        bitmap_register0.write((bit<32>)meta.my_metadata.bitmap_hash_val0, meta.my_metadata.bitmap_val0);
        bitmap_register1.write((bit<32>)meta.my_metadata.bitmap_hash_val1, meta.my_metadata.bitmap_val1);
    }

    action action_bitmap_existing_pair() {     

        bit<32> tmp1;

        bitmap_register1.read(tmp1, (bit<32>)meta.my_metadata.bitmap_hash_val1);
        meta.my_metadata.bitmap_val1 = tmp1;
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

    table table_get_count_min_hash_0_val {
        actions = {
            action_get_count_min_hash_0_val;
        }
        default_action = action_get_count_min_hash_0_val();
    }

    table table_get_count_min_hash_1_val {
        actions = {
            action_get_count_min_hash_1_val;
        }
        default_action = action_get_count_min_hash_1_val();
    }

    table table_get_count_min_hash_2_val {
        actions = {
            action_get_count_min_hash_2_val;
        }
        default_action = action_get_count_min_hash_2_val();
    }        

    table table_count_min_sketch_incr { 
        actions = {
            action_count_min_sketch_incr;
        }
        default_action = action_count_min_sketch_incr();
    }    

    table table_count_min_register_write { 
        actions = {
            action_count_min_register_write;
        }
        default_action = action_count_min_register_write();
    }   

    table table_bitmap_hash_0_val { 
        actions = {
            action_bitmap_hash_0_val;
        }
        default_action = action_bitmap_hash_0_val();
    }

    table table_bitmap_hash_1_val { 
        actions = {
            action_bitmap_hash_1_val;
        }
        default_action = action_bitmap_hash_1_val();
    }

    table table_bitmap_check_pair { 
        actions = {
            action_bitmap_check_pair;
        }
        default_action = action_bitmap_check_pair();
    }

    table table_bitmap_new_pair { 
        actions = {
            action_bitmap_new_pair;
        }
        default_action = action_bitmap_new_pair();
    }

    table table_bitmap_existing_pair { 
        actions = {
            action_bitmap_existing_pair;
        }
        default_action = action_bitmap_existing_pair();
    }

    // table table_send_to_cpu { 
    //     actions = {
    //         send_to_cpu;
    //     }
    //     default_action = send_to_cpu();
    // }                 


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
                
                // Count-min Sketch 
                
                table_get_count_min_hash_0_val.apply();
                table_get_count_min_hash_1_val.apply();
                table_get_count_min_hash_2_val.apply();
                table_count_min_sketch_incr.apply();
                
                meta.my_metadata.count_min_val = meta.my_metadata.count_min_val0;
                meta.my_metadata.count_min_hash = meta.my_metadata.count_min_hash_val0;
                
                if (meta.my_metadata.count_min_val > meta.my_metadata.count_min_val1) {
                    meta.my_metadata.count_min_val = meta.my_metadata.count_min_val1;
                    meta.my_metadata.count_min_hash = meta.my_metadata.count_min_hash_val1;
                }
                
                if (meta.my_metadata.count_min_val > meta.my_metadata.count_min_val2) {
                    meta.my_metadata.count_min_val = meta.my_metadata.count_min_val2;
                    meta.my_metadata.count_min_hash = meta.my_metadata.count_min_hash_val2;
                }

                table_count_min_register_write.apply();  
                
                // Bitmap Sketch
                
                table_bitmap_hash_0_val.apply();
                table_bitmap_hash_1_val.apply();
     
                // Check the bitmap value for the (ip src, ip dst) pair
                table_bitmap_check_pair.apply(); 
                if (meta.my_metadata.bitmap_val0 == 0) {
                    // if the value is 0, we write the bitmap value on register0 and increase the counter
                    // for the ip src on register1 (meaning that we have a new pair)
                    table_bitmap_new_pair.apply();
                } else {
                    // if the value is 1, we do nothing (the pair is already accounted for)
                    table_bitmap_existing_pair.apply();
                }
                // table_send_to_cpu.apply();

                // Packet hit an entry in t_l2_fwd table. A forwarding action
                // has already been taken. No need to apply other tables, exit
                // this control block.                
                return;
            }
        }

        /*
        if (standard_metadata.egress_spec < MAX_PORTS) {
            tx_port_counter.count((bit<32>) standard_metadata.egress_spec);
        }
        if (standard_metadata.ingress_port < MAX_PORTS) {
            rx_port_counter.count((bit<32>) standard_metadata.ingress_port);
        }
        */
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