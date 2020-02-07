control c_threshold(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

    // Stores the total packet count.
    register<bit<32>>(1)  traffic_global_register;

    // Stores the total packet count, excluding the packets in the current stage (for each flow).
    register<bit<32>>(REG_SKETCH_SIZE)  traffic_global_flow_register;
    // Stores the packet count for the current stage (for each flow).
    register<bit<32>>(REG_SKETCH_SIZE)  traffic_flow_register;
    // Store the timestamp corresponding to the beginning of the current stage (for each flow).
    register<bit<48>>(REG_SKETCH_SIZE)  time_flow_register;

    // Increase the global traffic counter.
    action global_traffic_counter_incr() {

        traffic_global_register.read(meta.threshold.global_traffic, (bit<32>)0); 
        meta.threshold.global_traffic = meta.threshold.global_traffic + 1;
        traffic_global_register.write((bit<32>)0, meta.threshold.global_traffic);
    }

    // Increase the traffic counter for a specific flow.
    action flow_traffic_counter_incr() {

        traffic_flow_register.read(meta.threshold.flow_traffic, (bit<32>)meta.threshold.hash_flow);
        meta.threshold.flow_traffic = meta.threshold.flow_traffic + 1;
        traffic_flow_register.write((bit<32>)meta.threshold.hash_flow, meta.threshold.flow_traffic);
    }

    // Update the time value for the current flow with the global timestamp.
    action time_flow_update() {
        time_flow_register.write((bit<32>)meta.threshold.hash_flow, standard_metadata.ingress_global_timestamp); 
    }

    // Reset the counters for a specific flow.
    action flow_traffic_counter_reset() {
        traffic_flow_register.write((bit<32>)meta.threshold.hash_flow, 0);
        traffic_global_flow_register.write((bit<32>)meta.threshold.hash_flow, meta.threshold.global_traffic);
    }

    action check_flow_time() {
        time_flow_register.read(meta.threshold.flow_time, (bit<32>)meta.threshold.hash_flow); 
    }    

    action check_flow_global_traffic() {
        traffic_global_flow_register.read(meta.threshold.flow_global_traffic, (bit<32>)meta.threshold.hash_flow);
    }

        action send_to_cpu_threshold() {

        // Packets sent to the controller needs to be prepended with the packet-in header.
        // By setting it valid we make sure it will be deparsed on the wire (see c_deparser).
        standard_metadata.egress_spec = CPU_PORT;
        hdr.packet_in.setValid();
        hdr.packet_in.ingress_port  = standard_metadata.ingress_port;
        hdr.packet_in.timestamp     = (bit<64>)standard_metadata.ingress_global_timestamp;
        hdr.packet_in.ip_src        = hdr.ipv4.src_addr;
        hdr.packet_in.ip_dst        = hdr.ipv4.dst_addr;
        hdr.packet_in.ip_proto      = (bit<9>)hdr.ipv4.protocol;
        hdr.packet_in.port_src      = meta.meta.l4_src_port;
        hdr.packet_in.port_dst      = meta.meta.l4_dst_port;
        hdr.packet_in.tcp_flags     = hdr.tcp.res ++ hdr.tcp.ecn ++ hdr.tcp.ctrl;
        hdr.packet_in.icmp_type     = (bit<9>)hdr.icmp.type;
        hdr.packet_in.icmp_code     = (bit<9>)hdr.icmp.code;
        hdr.packet_in.cm_ip         = meta.cm.sketch_ip_final;
        hdr.packet_in.cm_5t         = meta.cm.sketch_5t_final;
        hdr.packet_in.bm_src        = meta.bm.sketch_1;
        hdr.packet_in.bm_dst        = meta.bm.sketch_2;
        hdr.packet_in.ams           = meta.ams.sketch_final;
    }

	apply {

        // The current threshold hash has already been calculated for the cm sketch.
        meta.threshold.hash_flow = meta.cm.hash_5t_0;

        global_traffic_counter_incr();
        flow_traffic_counter_incr();

        // Obtain the last time value stored for the current flow.
        check_flow_time();

        // If the last time value stored is 0, the current flow is considered new.
        // We then update its time value with the current global timestamp.  
        if (meta.threshold.flow_time == (bit<48>)0) {
            time_flow_update();
        }

        // Verify if more than x microseconds have elapsed since the last threshold check for the current flow.
        if ((standard_metadata.ingress_global_timestamp - meta.threshold.flow_time) > (bit<48>)5000000) {
            
            // Obtain the global traffic value corresponding to the last stage for the current flow.
            check_flow_global_traffic();

            // Check if the flow traffic at the current stage corresponds to more than 10% of the total traffic.
            // If so, we send the current flow stats to the controller.
            if ((meta.threshold.flow_traffic * 10) > (meta.threshold.global_traffic - meta.threshold.flow_global_traffic)) {

                // Specify a packet_in header containing all flow stats.
                send_to_cpu_threshold();

                // As the threshold has been exceeded, a new phase will start for the current flow.
                // As such, we update the time value and reset the traffic counters.
                time_flow_update();
                flow_traffic_counter_reset();
            }
        }
	}
}
