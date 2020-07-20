#include <core.p4>
#include <v1model.p4>

#include "includes/constants.p4"
#include "includes/registers.p4"
#include "includes/headers.p4"
#include "includes/parser.p4"
#include "includes/deparser.p4"
#include "includes/set_reg.p4"
#include "includes/epoch.p4"
#include "includes/sketches/cm_5t.p4"
#include "includes/sketches/cm_ip.p4"
#include "includes/sketches/bm_src.p4"
#include "includes/sketches/bm_dst.p4"

//------------------------------------------------------------------------------
// INGRESS PIPELINE
//------------------------------------------------------------------------------

control c_ingress(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

	c_cm_5t() 	cm_5t;
	c_cm_ip()	cm_ip;
	c_bm_src()	bm_src; 
	c_bm_dst()	bm_dst; 
	
	action drop() {
		mark_to_drop(standard_metadata);
	}
	
	action ipv4_forward(bit<48> dst_addr, bit<9> port) {
		standard_metadata.egress_spec = port;
		hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
		hdr.ethernet.dst_addr = dst_addr;
		hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
	}

	action sketch_config(bit<32> cm_5t_flag, bit<32> cm_ip_flag, bit<32> bm_src_flag, bit<32> bm_dst_flag, bit<32> virtual_register_num, bit<32> hash_size) {
		
		meta.reg.cm_5t = cm_5t_flag;
		meta.reg.cm_ip = cm_ip_flag;
		meta.reg.bm_src = bm_src_flag;
		meta.reg.bm_dst = bm_dst_flag;

		meta.reg.virtual_register_num = virtual_register_num;
		meta.reg.hash_size = hash_size;
	}

	action epoch_read() {
		register_epoch.read(meta.epoch.current_epoch, 0);
	}	
		
	table t_fwd {
		key = {
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
			ipv4_forward;
			drop;
			NoAction;
		}
		size = 1024;
		default_action = drop();
	}

	table t_sketches {
		key = {
			hdr.ethernet.ether_type: exact;
		}
		actions = {
			sketch_config;
		}
	}
	
	apply {
		
		if (t_fwd.apply().hit) {

			// Check which sketches are active.
			// Update the number of required virtual registers accordingly.			

			if (t_sketches.apply().hit) {

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
			}
			
			return;
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