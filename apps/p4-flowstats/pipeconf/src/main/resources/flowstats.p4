
#include <core.p4>
#include <v1model.p4>

#include "includes/constants.p4"
#include "includes/headers.p4"
#include "includes/parser.p4"
#include "includes/deparser.p4"
#include "includes/cmSketch.p4"
#include "includes/bmSketch.p4"
#include "includes/threshold.p4"

//------------------------------------------------------------------------------
// INGRESS PIPELINE
//------------------------------------------------------------------------------

control c_ingress(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

    // We use these counters to count packets/bytes received/sent on each port.
    // For each counter we instantiate a number of cells equal to MAX_PORTS.
    counter(MAX_PORTS, CounterType.packets_and_bytes) tx_port_counter;
    counter(MAX_PORTS, CounterType.packets_and_bytes) rx_port_counter;

	// control blocks instantiations
	c_cmSketch()    cm;
    c_bmSketch()    bm;
    c_threshold()   threshold;
    // c_karySketch()  kary;

    action send_to_cpu() {
        // Packets sent to the controller needs to be prepended with the packet-in header.
        // By setting it valid we make sure it will be deparsed on the wire (see c_deparser).
        standard_metadata.egress_spec = CPU_PORT;
        hdr.packet_in.setValid();
        hdr.packet_in.ingress_port = standard_metadata.ingress_port;
        // hdr.packet_in.threshold_hash = standard_metadata.ingress_port;
    }

    action set_out_port(port_t port) {
        // Specifies the output port for this packet by setting the corresponding metadata.
        standard_metadata.egress_spec = port;
    }

    action _drop() {}

    // Table counter used to count packets and bytes matched by each entry of t_l2_fwd table.
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
            hdr.udp.src_port                : ternary;
            hdr.udp.dst_port                : ternary;
            hdr.tcp.src_port                : ternary;
            hdr.tcp.dst_port                : ternary;
            hdr.tcp.res                     : ternary;
            hdr.tcp.ecn                     : ternary;
            hdr.tcp.ctrl                    : ternary;
            hdr.icmp.type                   : ternary;
            hdr.icmp.code                   : ternary;
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
            // Applies table t_l2_fwd to the packet.   
            if (t_l2_fwd.apply().hit) {
  
				cm.apply(hdr, meta, standard_metadata);                 
                bm.apply(hdr, meta, standard_metadata); 

                threshold.apply(hdr, meta, standard_metadata);           

                // Packet hit an entry in t_l2_fwd table. A forwarding action has already been taken.
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
