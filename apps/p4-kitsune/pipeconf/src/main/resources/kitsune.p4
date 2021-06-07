#include <core.p4>
#include <v1model.p4>

#include "includes/constants.p4"
#include "includes/registers.p4"
#include "includes/headers.p4"
#include "includes/parser.p4"
#include "includes/deparser.p4"
#include "includes/set_reg.p4"
#include "includes/sketch_read.p4"
#include "includes/sketch_write.p4"
#include "includes/threshold.p4"
#include "includes/hash_calc.p4"
#include "includes/sketches/cm_ip_cnt.p4"
#include "includes/sketches/cm_ip_len.p4"
#include "includes/sketches/cm_ip_port_dst_cnt.p4"
#include "includes/sketches/cm_ip_port_dst_len.p4"
#include "includes/sketches/cm_ip_tcp_flags_cnt.p4"
#include "includes/sketches/cm_ip_tcp_flags_len.p4"
#include "includes/sketches/cm_ip_proto_cnt.p4"
#include "includes/sketches/cm_ip_proto_len.p4"
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
    c_hash_calc()           hash_calc;
    c_cm_ip_cnt()           cm_ip_cnt;
    c_cm_ip_len()           cm_ip_len;
    c_cm_ip_port_dst_cnt()  cm_ip_port_dst_cnt;
    c_cm_ip_port_dst_len()  cm_ip_port_dst_len;
    c_cm_ip_tcp_flags_cnt() cm_ip_tcp_flags_cnt;
    c_cm_ip_tcp_flags_len() cm_ip_tcp_flags_len;
    c_cm_ip_proto_cnt()     cm_ip_proto_cnt;
    c_cm_ip_proto_len()     cm_ip_proto_len;
    c_bm_ip_src()           bm_ip_src;              // Number of different IPs contacted by a src IP.
    c_bm_ip_dst()           bm_ip_dst;              // Number of different IPs contacted by a dst IP.
    c_bm_ip_src_port_src()  bm_ip_src_port_src;     // Number of different src ports used by a src IP.
    c_bm_ip_src_port_dst()  bm_ip_src_port_dst;     // Number of different dst ports contacted by a src IP.
    c_bm_ip_dst_port_src()  bm_ip_dst_port_src;     // Number of different src ports used to contact a src IP.
    c_bm_ip_dst_port_dst()  bm_ip_dst_port_dst;     // Number of different dst ports contacted for each dst IP.
    c_ams() 	            ams;
    c_mv()                  mv;
	
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

    // Values defined by the operator through the t_sketches table rules.
    // The sketch flags define which sketches are to be executed.
    // The hash size is used in the various sketch hash functions.
    action sketch_config(bit<1> cm_ip_cnt_flag, bit<1> cm_ip_len_flag, bit<1> cm_ip_port_dst_cnt_flag,
                         bit<1> cm_ip_port_dst_len_flag, bit<1> cm_ip_tcp_flags_cnt_flag,
                         bit<1> cm_ip_tcp_flags_len_flag, bit<1> cm_ip_proto_cnt_flag, bit<1> cm_ip_proto_len_flag,
                         bit<1> bm_ip_src_flag, bit<1> bm_ip_dst_flag, bit<1> bm_ip_src_port_src_flag,
                         bit<1> bm_ip_src_port_dst_flag, bit<1> bm_ip_dst_port_src_flag, bit<1> bm_ip_dst_port_dst_flag,
                         bit<1> ams_flag, bit<1> mv_flag, bit<32> hash_size, bit<64> thres_alert, bit<64> thres_interval,
                         bit<8> decay_factor) {
		
        meta.reg.cm_ip_cnt = cm_ip_cnt_flag;
        meta.reg.cm_ip_len = cm_ip_len_flag;
        meta.reg.cm_ip_port_dst_cnt = cm_ip_port_dst_cnt_flag;
        meta.reg.cm_ip_port_dst_len = cm_ip_port_dst_len_flag;
        meta.reg.cm_ip_tcp_flags_cnt = cm_ip_tcp_flags_cnt_flag;
        meta.reg.cm_ip_tcp_flags_len = cm_ip_tcp_flags_len_flag;
        meta.reg.cm_ip_proto_cnt = cm_ip_proto_cnt_flag;
        meta.reg.cm_ip_proto_len = cm_ip_proto_len_flag;
        meta.reg.bm_ip_src = bm_ip_src_flag;
        meta.reg.bm_ip_dst = bm_ip_dst_flag;
        meta.reg.bm_ip_src_port_src = bm_ip_src_port_src_flag;
        meta.reg.bm_ip_src_port_dst = bm_ip_src_port_dst_flag;
        meta.reg.bm_ip_dst_port_src = bm_ip_dst_port_src_flag;
        meta.reg.bm_ip_dst_port_dst = bm_ip_dst_port_dst_flag;
        meta.reg.ams = ams_flag;
        meta.reg.mv = mv_flag;
        meta.reg.hash_size = hash_size;
        meta.thres.alert = thres_alert;
        meta.thres.interval = thres_interval;
        meta.decay.factor = decay_factor;
    }

    // Table counter used to count packets and bytes matched by each entry of t_fwd table.
    direct_counter(CounterType.packets_and_bytes) fwd_counter;	

    // ONOS requires ether_type as part of the forwarding table rules.
    // By using only these two features, we avoid filling the ONOS flow table during evaluation tests.
    table t_fwd {
        key = {
            standard_metadata.ingress_port  : ternary;
            hdr.ethernet.ether_type         : ternary;
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

    // Table defining which sketches are active and the correspondent hash size.
    // Configuring the sketches through a table allows the operator to easily modify them during runtime.
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

        meta.reg.current_reg = 0;
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

                // Check which sketches are active (flag value == 0).
                // Update the number of required virtual registers accordingly.

                if (hdr.ipv4.isValid()) {
					
                    t_sketches.apply();

                    // Hash calculations.
                    hash_calc.apply(hdr, meta, standard_metadata);

                    // Timestamp recording (old and current) for the damped window statistics calculation.

                    reg_ts_old.read(meta.decay.ts_old, meta.hash.ip_0);
                    meta.decay.ts_current = (int<48>)standard_metadata.ingress_global_timestamp;
                    meta.decay.ts_interval = meta.decay.ts_current - meta.decay.ts_old;
                    // Bit-shift by 19 is equivalent to the microseconds -> seconds convertion.
                    meta.decay.value = (bit<8>)(bit<48>)(meta.decay.ts_interval >> 19) >> meta.decay.factor;

                    reg_ts_old.write(meta.hash.ip_0, meta.decay.ts_current);

                    // Execute the active sketching algorithms.
                    // Defined by the operator through the t_sketches table rules.

                    if (meta.reg.cm_ip_cnt == 0) cm_ip_cnt.apply(hdr, meta, standard_metadata);
                    if (meta.reg.cm_ip_len == 0) cm_ip_len.apply(hdr, meta, standard_metadata);

                    // The count-min sketch with inputs (ip src, ip dst, port dst) is only calculated
                    // if the current dst port is 21, 22, or 80.

                    if ((meta.reg.cm_ip_port_dst_cnt == 0) &&
                        ((hdr.tcp.dst_port == 21) || (hdr.tcp.dst_port == 22) || (hdr.tcp.dst_port == 80))) {
                        cm_ip_port_dst_cnt.apply(hdr, meta, standard_metadata);
                    }

                    if ((meta.reg.cm_ip_port_dst_len == 0) &&
                        ((hdr.tcp.dst_port == 21) || (hdr.tcp.dst_port == 22) || (hdr.tcp.dst_port == 80))) {
                        cm_ip_port_dst_len.apply(hdr, meta, standard_metadata);
                    }

                    // The count-min sketch with inputs (ip src, ip dst, tcp flags) is only calculated
                    // if the current tcp flags values is 2, 4, or 16 .

                    if ((meta.reg.cm_ip_tcp_flags_cnt == 0) &&
                        (((hdr.tcp.res ++ hdr.tcp.ecn ++ hdr.tcp.ctrl) == 2) ||
                         ((hdr.tcp.res ++ hdr.tcp.ecn ++ hdr.tcp.ctrl) == 4) ||
                         ((hdr.tcp.res ++ hdr.tcp.ecn ++ hdr.tcp.ctrl) == 16))) {
                        cm_ip_tcp_flags_cnt.apply(hdr, meta, standard_metadata);
                    }

                    if ((meta.reg.cm_ip_tcp_flags_len == 0) &&
                        (((hdr.tcp.res ++ hdr.tcp.ecn ++ hdr.tcp.ctrl) == 2) ||
                         ((hdr.tcp.res ++ hdr.tcp.ecn ++ hdr.tcp.ctrl) == 4) ||
                         ((hdr.tcp.res ++ hdr.tcp.ecn ++ hdr.tcp.ctrl) == 16))) {
                        cm_ip_tcp_flags_len.apply(hdr, meta, standard_metadata);
                    }

                    // The count-min sketch with inputs (ip src, ip dst, ip proto) is only calculated
                    // if the current ip proto value is 1.

                    if ((meta.reg.cm_ip_proto_cnt == 0) && (hdr.ipv4.protocol == 1)) {
                        cm_ip_proto_cnt.apply(hdr, meta, standard_metadata);
                    }

                    if ((meta.reg.cm_ip_proto_len == 0) && (hdr.ipv4.protocol == 1)) {
                        cm_ip_proto_len.apply(hdr, meta, standard_metadata);
                    }

                    if (meta.reg.bm_ip_src == 0)            bm_ip_src.apply(hdr, meta, standard_metadata);
                    if (meta.reg.bm_ip_dst == 0)            bm_ip_dst.apply(hdr, meta, standard_metadata);
                    if (meta.reg.bm_ip_src_port_src == 0)   bm_ip_src_port_src.apply(hdr, meta, standard_metadata);
                    if (meta.reg.bm_ip_src_port_dst == 0)   bm_ip_src_port_dst.apply(hdr, meta, standard_metadata);
                    if (meta.reg.bm_ip_dst_port_src == 0)   bm_ip_dst_port_src.apply(hdr, meta, standard_metadata);
                    if (meta.reg.bm_ip_dst_port_dst == 0)   bm_ip_dst_port_dst.apply(hdr, meta, standard_metadata);
                    if (meta.reg.ams == 0)                  ams.apply(hdr, meta, standard_metadata);
                    if (meta.reg.mv == 0)                   mv.apply(hdr, meta, standard_metadata);
                }

                // Apply the threshold control block, to check if the current flow exceeds the defined threshold.
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