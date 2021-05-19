control c_threshold(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

    // Stores the total packet count.
    register<bit<32>>(1)  reg_thres_global_traffic;
    // Stores the total packet count, excluding the packets in the current stage (for each flow).
    register<bit<32>>(32768) reg_thres_flow_global_traffic;
    // Stores the packet count for the current stage (for each flow).
    register<bit<32>>(32768) reg_thres_flow_traffic;

    // Increase the global traffic counter.
    action global_traffic_incr() {
        reg_thres_global_traffic.read(meta.threshold.global_traffic, (bit<32>)0);
        meta.threshold.global_traffic = meta.threshold.global_traffic + 1;
        reg_thres_global_traffic.write((bit<32>)0, meta.threshold.global_traffic);
    }

    // Increase the traffic counter for a specific flow.
    action flow_traffic_incr() {
        reg_thres_flow_traffic.read(meta.threshold.flow_traffic, (bit<32>)meta.threshold.hash_flow);
        meta.threshold.flow_traffic = meta.threshold.flow_traffic + 1;
        reg_thres_flow_traffic.write((bit<32>)meta.threshold.hash_flow, meta.threshold.flow_traffic);
    }

    // Update the global traffic counter for the current flow with the global traffic counter.
    action flow_global_traffic_update() {
        reg_thres_flow_global_traffic.write((bit<32>)meta.threshold.hash_flow, meta.threshold.global_traffic);
    }

    // Reset the counters for a specific flow.
    action flow_traffic_reset() {
        reg_thres_flow_traffic.write((bit<32>)meta.threshold.hash_flow, 0);
        reg_thres_flow_global_traffic.write((bit<32>)meta.threshold.hash_flow, meta.threshold.global_traffic);
    }

    // Obtain the global traffic value corresponding to the last stage for the current flow.
    action check_flow_global_traffic() {
        reg_thres_flow_global_traffic.read(meta.threshold.flow_global_traffic, (bit<32>)meta.threshold.hash_flow);
    }

    // Specify a packet_in header containing all flow stats.
    action send_to_cpu_threshold() {

        // Packets sent to the controller needs to be prepended with the packet-in header.
        // By setting it valid we make sure it will be deparsed on the wire (see c_deparser).
        standard_metadata.egress_spec = CPU_PORT;
        hdr.packet_in.setValid();
        hdr.packet_in.ingress_port          = standard_metadata.ingress_port;
        hdr.packet_in.ip_src                = hdr.ipv4.src_addr;
        hdr.packet_in.ip_dst                = hdr.ipv4.dst_addr;
        hdr.packet_in.cm_ip                 = meta.cm_ip.sketch_final;
        hdr.packet_in.bm_ip_src             = meta.bm_ip_src.sketch_1;
        hdr.packet_in.bm_ip_dst             = meta.bm_ip_dst.sketch_1;
        hdr.packet_in.bm_ip_src_port_src    = meta.bm_ip_src_port_src.sketch_1;
        hdr.packet_in.bm_ip_src_port_dst    = meta.bm_ip_src_port_dst.sketch_1;
        hdr.packet_in.bm_ip_dst_port_src    = meta.bm_ip_dst_port_src.sketch_1;
        hdr.packet_in.bm_ip_dst_port_dst    = meta.bm_ip_dst_port_dst.sketch_1;
        hdr.packet_in.ams                   = meta.ams.sketch_final;

        if (hdr.tcp.dst_port == 21) hdr.packet_in.cm_ip_port_21 = meta.cm_ip_port_dst.sketch_final;
        if (hdr.tcp.dst_port == 22) hdr.packet_in.cm_ip_port_22 = meta.cm_ip_port_dst.sketch_final;
        if (hdr.tcp.dst_port == 80) hdr.packet_in.cm_ip_port_80 = meta.cm_ip_port_dst.sketch_final;
        if ((hdr.tcp.res ++ hdr.tcp.ecn ++ hdr.tcp.ctrl) == 2) hdr.packet_in.cm_ip_tcp_syn = meta.cm_ip_tcp_flags.sketch_final;
        if ((hdr.tcp.res ++ hdr.tcp.ecn ++ hdr.tcp.ctrl) == 16) hdr.packet_in.cm_ip_tcp_ack = meta.cm_ip_tcp_flags.sketch_final;
        if ((hdr.tcp.res ++ hdr.tcp.ecn ++ hdr.tcp.ctrl) == 4) hdr.packet_in.cm_ip_tcp_rst = meta.cm_ip_tcp_flags.sketch_final;
        if (hdr.ipv4.protocol == 1) hdr.packet_in.cm_ip_icmp = meta.cm_ip_proto.sketch_final;

        // Check if the current MV sketch key (strongest candidate) matches the current flow key.
        if (hdr.ipv4.src_addr ++ hdr.ipv4.dst_addr == meta.mv.key_temp) {
            hdr.packet_in.mv = (bit<9>)0;
        } else {
            hdr.packet_in.mv = (bit<9>)1;
        }
    }

    apply {

        // The current threshold hash has already been calculated.
        meta.threshold.hash_flow = meta.hash.ip_src_ip_dst_0;

        // Increase the global and flow-specific traffic counters and check the last flow global traffic counter stored.
        global_traffic_incr();
        flow_traffic_incr();
        check_flow_global_traffic();

        // If the last flow global traffic value stored is 0, the current flow is considered new.
        // We then update its value with the current global traffic counter.
        if (meta.threshold.flow_global_traffic == 0) {
            flow_global_traffic_update();
        }

        // Verify if more than x packets have traversed the switch since the last threshold check for the current flow.
        if ((meta.threshold.global_traffic - meta.threshold.flow_global_traffic) > 5000) {

            // Check if the flow traffic at the current stage corresponds to more than 5% of the total traffic.
            // If so, we send the current flow stats to the controller.
            if ((meta.threshold.flow_traffic * 40) > (meta.threshold.global_traffic - meta.threshold.flow_global_traffic)) {
                send_to_cpu_threshold();
            }

            // Either the check did not trigger an alert, or the threshold has been exceeded.
            // A new phase will start for the current flow, so we reset its traffic counters.
            flow_traffic_reset();
        }
    }
}
