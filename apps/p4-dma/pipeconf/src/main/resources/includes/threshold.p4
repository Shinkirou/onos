control c_threshold(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

    // Store the total packet count/length.
    register<bit<32>>(1)  reg_global_pkt_cnt;
    register<bit<32>>(1)  reg_global_pkt_len;
    // Store the total packet count/length, excluding the packets in the current stage (for each flow).
    register<bit<32>>(32768) reg_flow_global_pkt_cnt;
    register<bit<32>>(32768) reg_flow_global_pkt_len;
    // Store the flow packet count/length, excluding the packets in the current stage (for each flow).
    register<bit<32>>(32768) reg_flow_pkt_cnt;
    register<bit<32>>(32768) reg_flow_pkt_len;

    // Increase the global traffic counters.
    action global_traffic_incr() {
        reg_global_pkt_cnt.read(meta.thres.global_pkt_cnt, (bit<32>)0);
        meta.thres.global_pkt_cnt = meta.thres.global_pkt_cnt + 1;
        reg_global_pkt_cnt.write((bit<32>)0, meta.thres.global_pkt_cnt);

        reg_global_pkt_len.read(meta.thres.global_pkt_len, (bit<32>)0);
        meta.thres.global_pkt_len = meta.thres.global_pkt_len + standard_metadata.packet_length;
        reg_global_pkt_len.write((bit<32>)0, meta.thres.global_pkt_len);
    }

    // Update the global traffic counter for the current flow with the global traffic counter.
    action flow_global_traffic_update() {
        reg_flow_global_pkt_cnt.write((bit<32>)meta.hash.ip_0, meta.thres.global_pkt_cnt);
        reg_flow_global_pkt_len.write((bit<32>)meta.hash.ip_0, meta.thres.global_pkt_len);
    }

    // Reset the counters for a specific flow.
    action flow_traffic_reset() {
        reg_flow_pkt_cnt.write((bit<32>)meta.hash.ip_0, meta.cm_ip_cnt.sketch_final);
        reg_flow_global_pkt_cnt.write((bit<32>)meta.hash.ip_0, meta.thres.global_pkt_cnt);
    }

    // Obtain the global traffic counters corresponding to the last stage for the current flow.
    action check_flow_global_traffic() {
        reg_flow_global_pkt_cnt.read(meta.thres.flow_global_pkt_cnt, (bit<32>)meta.hash.ip_0);
        reg_flow_global_pkt_len.read(meta.thres.flow_global_pkt_len, (bit<32>)meta.hash.ip_0);
    }

    // Obtain the total packet count corresponding to the last stage for the current flow.
    action check_flow_pkt_cnt() {
        reg_flow_pkt_cnt.read(meta.thres.flow_pkt_cnt, (bit<32>)meta.hash.ip_0);
    }

    // Obtain the total packet length corresponding to the last stage for the current flow.
    action check_flow_pkt_len() {
        reg_flow_pkt_len.read(meta.thres.flow_pkt_len, (bit<32>)meta.hash.ip_0);
    }

    // Specify a packet_in header containing all flow stats.
    action send_to_cpu_thres() {

        // Packets sent to the controller needs to be prepended with the packet-in header.
        // By setting it valid we make sure it will be deparsed on the wire (see c_deparser).
        standard_metadata.egress_spec = CPU_PORT;
        hdr.packet_in.setValid();
        hdr.packet_in.ingress_port          = standard_metadata.ingress_port;
        hdr.packet_in.ip_src                = hdr.ipv4.src_addr;
        hdr.packet_in.ip_dst                = hdr.ipv4.dst_addr;
        hdr.packet_in.cm_ip_cnt             = meta.cm_ip_cnt.sketch_final;
        hdr.packet_in.cm_ip_len             = meta.cm_ip_len.sketch_final;
        hdr.packet_in.bm_ip_src             = meta.bm_ip_src.sketch_1;
        hdr.packet_in.bm_ip_dst             = meta.bm_ip_dst.sketch_1;
        hdr.packet_in.bm_ip_src_port_src    = meta.bm_ip_src_port_src.sketch_1;
        hdr.packet_in.bm_ip_src_port_dst    = meta.bm_ip_src_port_dst.sketch_1;
        hdr.packet_in.bm_ip_dst_port_src    = meta.bm_ip_dst_port_src.sketch_1;
        hdr.packet_in.bm_ip_dst_port_dst    = meta.bm_ip_dst_port_dst.sketch_1;
        hdr.packet_in.ams                   = meta.ams.sketch_final;

        if (hdr.tcp.dst_port == 21) {
            hdr.packet_in.cm_ip_port_21_cnt = meta.cm_ip_port_dst_cnt.sketch_final;
            hdr.packet_in.cm_ip_port_21_len = meta.cm_ip_port_dst_len.sketch_final;
        }
        if (hdr.tcp.dst_port == 22) {
            hdr.packet_in.cm_ip_port_22_cnt = meta.cm_ip_port_dst_cnt.sketch_final;
            hdr.packet_in.cm_ip_port_22_len = meta.cm_ip_port_dst_len.sketch_final;
        }
        if (hdr.tcp.dst_port == 80) {
            hdr.packet_in.cm_ip_port_80_cnt = meta.cm_ip_port_dst_cnt.sketch_final;
            hdr.packet_in.cm_ip_port_80_len = meta.cm_ip_port_dst_len.sketch_final;
        }
        if ((hdr.tcp.res ++ hdr.tcp.ecn ++ hdr.tcp.ctrl) == 2) {
            hdr.packet_in.cm_ip_tcp_syn_cnt = meta.cm_ip_tcp_flags_cnt.sketch_final;
            hdr.packet_in.cm_ip_tcp_syn_len = meta.cm_ip_tcp_flags_len.sketch_final;
        }

        if ((hdr.tcp.res ++ hdr.tcp.ecn ++ hdr.tcp.ctrl) == 16) {
            hdr.packet_in.cm_ip_tcp_ack_cnt = meta.cm_ip_tcp_flags_cnt.sketch_final;
            hdr.packet_in.cm_ip_tcp_ack_len = meta.cm_ip_tcp_flags_len.sketch_final;
        }

        if ((hdr.tcp.res ++ hdr.tcp.ecn ++ hdr.tcp.ctrl) == 4) {
            hdr.packet_in.cm_ip_tcp_rst_cnt = meta.cm_ip_tcp_flags_cnt.sketch_final;
            hdr.packet_in.cm_ip_tcp_rst_len = meta.cm_ip_tcp_flags_len.sketch_final;
        }

        if (hdr.ipv4.protocol == 1) {
            hdr.packet_in.cm_ip_icmp_cnt = meta.cm_ip_proto_cnt.sketch_final;
            hdr.packet_in.cm_ip_icmp_len = meta.cm_ip_proto_len.sketch_final;
        }

        // Check if the current MV sketch key (strongest candidate) matches the current flow key.
        if (hdr.ipv4.src_addr ++ hdr.ipv4.dst_addr == meta.mv.key_temp) {
            hdr.packet_in.mv = (bit<9>)0;
        } else {
            hdr.packet_in.mv = (bit<9>)1;
        }
    }

    apply {

        // Increase the global and flow-specific traffic counters and check the last flow global traffic counter stored.
        global_traffic_incr();
        check_flow_global_traffic();

        // If the last flow global traffic value stored is 0, the current flow is considered new.
        // We then update its value with the current global traffic counter.
        if (meta.thres.flow_global_pkt_cnt == 0) flow_global_traffic_update();

        // Verify if more than x packets have traversed the switch since the last threshold check for the current flow.
        if ((meta.thres.global_pkt_cnt - meta.thres.flow_global_pkt_cnt) > 5000) {

            check_flow_pkt_cnt();

            // Check if the flow traffic at the current stage corresponds to more than 5% of the total traffic.
            // If so, we send the current flow stats to the controller.
            if (((meta.cm_ip_cnt.sketch_final - meta.thres.flow_pkt_cnt) * 40) > (meta.thres.global_pkt_cnt - meta.thres.flow_global_pkt_cnt)) {
                send_to_cpu_thres();
            } else {

                check_flow_pkt_len();

                if (((meta.cm_ip_len.sketch_final - meta.thres.flow_pkt_len) * 40) > (meta.thres.global_pkt_len - meta.thres.flow_global_pkt_len)) {
                    send_to_cpu_thres();
                }
            }

            // Either the check did not trigger an alert, or the threshold has been exceeded.
            // A new phase will start for the current flow, so we reset its traffic counters.
            flow_traffic_reset();
        }
    }
}
