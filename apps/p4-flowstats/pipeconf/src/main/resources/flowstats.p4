
#include <core.p4>
#include <v1model.p4>

#include "includes/constants.p4"
#include "includes/headers.p4"
#include "includes/parser.p4"
#include "includes/deparser.p4"
#include "includes/threshold.p4"
#include "includes/sketches/cm.p4"
#include "includes/sketches/bm_ip_src.p4"
#include "includes/sketches/bm_ip_dst.p4"
#include "includes/sketches/bm_ip_src_port_src.p4"
#include "includes/sketches/bm_ip_src_port_dst.p4"
#include "includes/sketches/bm_ip_dst_port_src.p4"
#include "includes/sketches/bm_ip_dst_port_dst.p4"
#include "includes/sketches/ams.p4"
#include "includes/sketches/mv.p4"

//------------------------------------------------------------------------------
// INGRESS PIPELINE
//------------------------------------------------------------------------------

control c_ingress(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

    // We use these counters to count packets/bytes received/sent on each port.
    // For each counter we instantiate a number of cells equal to MAX_PORTS.
    counter(MAX_PORTS, CounterType.packets_and_bytes) tx_port_counter;
    counter(MAX_PORTS, CounterType.packets_and_bytes) rx_port_counter;

    // Control block instantiations.
    c_threshold()           threshold;
    c_cm()                  cm;
    c_bm_ip_src()           bm_ip_src;              // Number of different IPs contacted by a src IP.
    c_bm_ip_dst()           bm_ip_dst;              // Number of different IPs contacted by a dst IP.
    c_bm_ip_src_port_src()  bm_ip_src_port_src;     // Number of different src ports used by a src IP.
    c_bm_ip_src_port_dst()  bm_ip_src_port_dst;     // Number of different dst ports contacted by a src IP.
    c_bm_ip_dst_port_src()  bm_ip_dst_port_src;     // Number of different src ports used to contact a src IP.
    c_bm_ip_dst_port_dst()  bm_ip_dst_port_dst;     // Number of different dst ports contacted for each dst IP.
    c_ams()                 ams;
    c_mv()                  mv;

    action send_to_cpu() {
        // Packets sent to the controller needs to be prepended with the packet-in header.
        // By setting it valid we make sure it will be deparsed on the wire (see c_deparser).
        standard_metadata.egress_spec = CPU_PORT;
        hdr.packet_in.setValid();
        hdr.packet_in.ingress_port = standard_metadata.ingress_port;
    }

    action set_out_port(port_t port) {
        // Specifies the output port for this packet by setting the corresponding metadata.
        standard_metadata.egress_spec = port;
    }

    action _drop() {}

    // Table counter used to count packets and bytes matched by each entry of t_fwd table.
    direct_counter(CounterType.packets_and_bytes) fwd_counter;

    table t_fwd {
        key = {
            standard_metadata.ingress_port  : ternary;
            hdr.ethernet.dst_addr           : ternary;
            hdr.ethernet.src_addr           : ternary;
            hdr.ethernet.ether_type         : ternary;
            hdr.ipv4.protocol               : ternary;
            hdr.ipv4.src_addr               : ternary;
            hdr.ipv4.dst_addr               : ternary;
        }
        actions = {
            set_out_port;
            send_to_cpu;
            _drop;
            NoAction;
        }
        default_action = NoAction();
        size = 524288;
        counters = fwd_counter;
    }              

    // Defines the processing applied by this control block. 
    // You can see this as the main function applied to every packet received by the switch.
    apply {
        if (standard_metadata.ingress_port == CPU_PORT) {

            // Packet received from CPU_PORT, this is a packet-out sent by the controller. 
            // Skip table processing, set the egress port as requested by the controller (packet_out header) and remove the packet_out header.           
            standard_metadata.egress_spec = hdr.packet_out.egress_port;
            hdr.packet_out.setInvalid();
        
        } else {
            
            // Packet received from data plane port.
            // Applies table t_fwd to the packet.   
            if (t_fwd.apply().hit) {

                cm.apply(hdr, meta, standard_metadata);
                bm_ip_src.apply(hdr, meta, standard_metadata);
                bm_ip_dst.apply(hdr, meta, standard_metadata);
                bm_ip_src_port_src.apply(hdr, meta, standard_metadata);
                bm_ip_src_port_dst.apply(hdr, meta, standard_metadata);
                bm_ip_dst_port_src.apply(hdr, meta, standard_metadata);
                bm_ip_dst_port_dst.apply(hdr, meta, standard_metadata);
                ams.apply(hdr, meta, standard_metadata);
                mv.apply(hdr, meta, standard_metadata);                              

                threshold.apply(hdr, meta, standard_metadata);

                // Packet hit an entry in t_fwd table. A forwarding action has already been taken.
                // No need to apply other tables, exit this control block.                
                return;
            }
        }

        if (standard_metadata.egress_spec < MAX_PORTS) {
            tx_port_counter.count((bit<32>) standard_metadata.egress_spec);
        }
        if (standard_metadata.ingress_port < MAX_PORTS) {
            rx_port_counter.count((bit<32>) standard_metadata.ingress_port);
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
// SWITCH INSTANTIATION
//------------------------------------------------------------------------------

V1Switch(c_parser(), c_verify_checksum(), c_ingress(), c_egress(), c_compute_checksum(), c_deparser()) main;
