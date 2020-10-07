#include <core.p4>
#include <v1model.p4>

#include "includes/constants.p4"
#include "includes/registers.p4"
#include "includes/headers.p4"
#include "includes/parser.p4"
#include "includes/deparser.p4"
#include "includes/set_reg.p4"
#include "includes/epoch.p4"
#include "includes/threshold.p4"
#include "includes/sketches/cm_5t.p4"
#include "includes/sketches/cm_ip.p4"
#include "includes/sketches/bm_src.p4"
#include "includes/sketches/bm_dst.p4"
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

    c_threshold() threshold;

	c_cm_5t() 	cm_5t;
	c_cm_ip()	cm_ip;
	c_bm_src()	bm_src; 
	c_bm_dst()	bm_dst;
	c_ams() 	ams;
	c_mv() 		mv;
	
	action _drop() {}
	
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

	action sketch_config(bit<32> cm_5t_flag, bit<32> cm_ip_flag, bit<32> bm_src_flag, bit<32> bm_dst_flag, bit<32> ams_flag, bit<32> mv_flag, bit<32> virtual_register_num, bit<32> hash_size) {
		
		meta.reg.cm_5t = cm_5t_flag;
		meta.reg.cm_ip = cm_ip_flag;
		meta.reg.bm_src = bm_src_flag;
		meta.reg.bm_dst = bm_dst_flag;
		meta.reg.ams = ams_flag;
		meta.reg.mv = mv_flag;

		meta.reg.virtual_register_num = virtual_register_num;
		meta.reg.hash_size = hash_size;
	}

	action epoch_read() {
		register_epoch.read(meta.epoch.current_epoch, 0);
	}

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
			hdr.udp.src_port                : ternary;
			hdr.udp.dst_port                : ternary;
			hdr.tcp.src_port                : ternary;
			hdr.tcp.dst_port                : ternary;
        }
        actions = {
            set_out_port;
            send_to_cpu;
            _drop;
            NoAction;
        }
        default_action = NoAction();
        size = 262144;
        counters = fwd_counter;
    }

	table t_sketches {
		key = {
			hdr.ethernet.ether_type : exact;
        }		
		actions = {
			sketch_config;
			_drop;
		}
		default_action = _drop();
	}
	
	apply {

		meta.reg.current_register = 0;
		meta.reg.current_index = 0;

        if (standard_metadata.ingress_port == CPU_PORT) {

            // Packet received from CPU_PORT, this is a packet-out sent by the controller. 
            // Skip table processing, set the egress port as requested by the controller (packet_out header) and remove the packet_out header.           
            standard_metadata.egress_spec = hdr.packet_out.egress_port;
            hdr.packet_out.setInvalid();

        } else {    	

            // Packet received from data plane port.
            // Applies table t_fwd to the packet. 				
			if (t_fwd.apply().hit) {

				// Check which sketches are active.
				// Update the number of required virtual registers accordingly.	

				if (hdr.ipv4.isValid()) {
					
					t_sketches.apply();

					// Read the epoch value bit defined by the operator in register_epoch.
					// This value will be used to check against the epoch values stored in the sketch registers.
					epoch_read();			

					// Execute the active sketching algorithms.
					// Defined by the operator through the t_sketches table rules.

					if (meta.reg.cm_5t == 0) {
						cm_5t.apply(hdr, meta, standard_metadata);
					}

					if (meta.reg.cm_ip == 0) {
						cm_ip.apply(hdr, meta, standard_metadata);
					}

					if (meta.reg.bm_src == 0) {
						bm_src.apply(hdr, meta, standard_metadata);
					}

					if (meta.reg.bm_dst == 0) {
						bm_dst.apply(hdr, meta, standard_metadata);
					}

					if (meta.reg.ams == 0) {
						ams.apply(hdr, meta, standard_metadata);
					}

					if (meta.reg.mv == 0) {
						mv.apply(hdr, meta, standard_metadata);
					}							
				}

				threshold.apply(hdr, meta, standard_metadata);
				
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

control c_egress(inout headers_t hdr,inout metadata_t meta, inout standard_metadata_t standard_metadata) {
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