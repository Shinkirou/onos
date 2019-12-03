control c_threshold(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

    register<bit<32>>(1)  traffic_global_register;

    register<bit<32>>(REG_SKETCH_SIZE)  traffic_global_flow_register;
    register<bit<32>>(REG_SKETCH_SIZE)  traffic_flow_register;
    register<bit<48>>(REG_SKETCH_SIZE)  time_flow_register;

    action threshold_hash() {
        hash(meta.threshold_meta.flow_hash, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.meta.l4_src_port, (bit<32>)meta.meta.l4_dst_port}, 
            (bit<32>)REG_SKETCH_SIZE);        
    }

    action threshold_hash2() {
        hash(meta.threshold_meta.flow_hash2, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr}, 
            (bit<32>)REG_SKETCH_SIZE);        
    }

    action threshold_hash3() {
        hash(meta.threshold_meta.flow_hash3, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.meta.l4_src_port}, 
            (bit<32>)REG_SKETCH_SIZE);        
    }        

    action threshold_hash4() {
        hash(meta.threshold_meta.flow_hash4, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.meta.l4_dst_port}, 
            (bit<32>)REG_SKETCH_SIZE);        
    }

    action check_flow_time() {
        time_flow_register.read(meta.threshold_meta.flow_time, (bit<32>)meta.threshold_meta.flow_hash); 
    }

    // Increase the global traffic counter.
    action traffic_counter_incr() {

        traffic_global_register.read(meta.threshold_meta.global_traffic, (bit<32>)0); 
        meta.threshold_meta.global_traffic = meta.threshold_meta.global_traffic + 1;
        traffic_global_register.write((bit<32>)0, meta.threshold_meta.global_traffic);
    }

    // Increase the traffic counter for a specific flow.
    action traffic_flow_incr() {

        traffic_flow_register.read(meta.threshold_meta.flow_traffic, (bit<32>)meta.threshold_meta.flow_hash);
        meta.threshold_meta.flow_traffic = meta.threshold_meta.flow_traffic + 1;
        traffic_flow_register.write((bit<32>)meta.threshold_meta.flow_hash, meta.threshold_meta.flow_traffic);
    }

    action time_flow_update() {
        time_flow_register.write((bit<32>)meta.threshold_meta.flow_hash, standard_metadata.ingress_global_timestamp); 
    }

    action flow_traffic_reset() {
        traffic_flow_register.write((bit<32>)meta.threshold_meta.flow_hash, 0);
        traffic_global_flow_register.write((bit<32>)meta.threshold_meta.flow_hash, meta.threshold_meta.global_traffic);
    }

    action check_flow_global_traffic() {
        traffic_global_flow_register.read(meta.threshold_meta.flow_global_traffic, (bit<32>)meta.threshold_meta.flow_hash);
    }

        action send_to_cpu_threshold() {

        // Packets sent to the controller needs to be prepended with the packet-in header.
        // By setting it valid we make sure it will be deparsed on the wire (see c_deparser).
        standard_metadata.egress_spec = CPU_PORT;
        hdr.packet_in.setValid();
        hdr.packet_in.ingress_port  = standard_metadata.ingress_port;
        hdr.packet_in.timestamp     = standard_metadata.ingress_global_timestamp;
        hdr.packet_in.ip_src        = hdr.ipv4.src_addr;
        hdr.packet_in.ip_dst        = hdr.ipv4.dst_addr;
        hdr.packet_in.ip_proto      = (bit<9>)hdr.ipv4.protocol;
        hdr.packet_in.port_src      = meta.meta.l4_src_port;
        hdr.packet_in.port_dst      = meta.meta.l4_dst_port;
        hdr.packet_in.icmp_type     = (bit<9>)hdr.icmp.type;
        hdr.packet_in.icmp_code     = (bit<9>)hdr.icmp.code;
        hdr.packet_in.cm_ip         = meta.cm_meta.cm_ip_final_sketch;
        hdr.packet_in.cm_5t         = meta.cm_meta.cm_5t_final_sketch;
        hdr.packet_in.bm_src        = meta.bm_meta.bm_1_sketch;
        hdr.packet_in.bm_dst        = meta.bm_meta.bm_2_sketch;
    }

	apply {

        threshold_hash();
        threshold_hash2();
        threshold_hash3();
        threshold_hash4();

        traffic_counter_incr();
        traffic_flow_incr();

        check_flow_time();

        if (meta.threshold_meta.flow_time == (bit<48>)0) {
            time_flow_update();
        }

        if ((standard_metadata.ingress_global_timestamp - meta.threshold_meta.flow_time) > (bit<48>)5000000) {
            
            check_flow_global_traffic();

            if ((meta.threshold_meta.flow_traffic * 10) > (meta.threshold_meta.global_traffic - meta.threshold_meta.flow_global_traffic)) {

                send_to_cpu_threshold();
                time_flow_update();
                flow_traffic_reset();
            }
        }
	}
}
