// Control block responsible for performing hash calculations, according to the current active sketches.

control c_hash_calc(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

    action hash_ip_0() {
       hash(meta.hash.ip_0,
           HashAlgorithm.crc32_custom,
           (bit<32>)0,
           {hdr.ipv4.src_addr, hdr.ipv4.dst_addr},
           (bit<32>)meta.reg.hash_size);
    }

    action hash_ip_1() {
       hash(meta.hash.ip_1,
           HashAlgorithm.crc32_custom,
           (bit<32>)0,
           {hdr.ipv4.src_addr, hdr.ipv4.dst_addr},
           (bit<32>)meta.reg.hash_size);
    }

    action hash_ip_2() {
       hash(meta.hash.ip_2,
           HashAlgorithm.crc32_custom,
           (bit<32>)0,
           {hdr.ipv4.src_addr, hdr.ipv4.dst_addr},
           (bit<32>)meta.reg.hash_size);
    }

    action hash_ip_port_dst_0() {
       hash(meta.hash.ip_port_dst_0,
           HashAlgorithm.crc32_custom,
           (bit<32>)0,
           {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.tcp.dst_port},
           (bit<32>)meta.reg.hash_size);
    }

    action hash_ip_port_dst_1() {
       hash(meta.hash.ip_port_dst_1,
           HashAlgorithm.crc32_custom,
           (bit<32>)0,
           {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.tcp.dst_port},
           (bit<32>)meta.reg.hash_size);
    }

    action hash_ip_port_dst_2() {
       hash(meta.hash.ip_port_dst_2,
           HashAlgorithm.crc32_custom,
           (bit<32>)0,
           {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.tcp.dst_port},
           (bit<32>)meta.reg.hash_size);
    }

    action hash_ip_tcp_flags_0() {
       hash(meta.hash.ip_tcp_flags_0,
           HashAlgorithm.crc32_custom,
           (bit<32>)0,
           {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.tcp.res ++ hdr.tcp.ecn ++ hdr.tcp.ctrl},
           (bit<32>)meta.reg.hash_size);
    }

    action hash_ip_tcp_flags_1() {
       hash(meta.hash.ip_tcp_flags_1,
           HashAlgorithm.crc32_custom,
           (bit<32>)0,
           {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.tcp.res ++ hdr.tcp.ecn ++ hdr.tcp.ctrl},
           (bit<32>)meta.reg.hash_size);
    }

    action hash_ip_tcp_flags_2() {
       hash(meta.hash.ip_tcp_flags_2,
           HashAlgorithm.crc32_custom,
           (bit<32>)0,
           {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.tcp.res ++ hdr.tcp.ecn ++ hdr.tcp.ctrl},
           (bit<32>)meta.reg.hash_size);
    }

    action hash_ip_proto_0() {
       hash(meta.hash.ip_proto_0,
           HashAlgorithm.crc32_custom,
           (bit<32>)0,
           {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.ipv4.protocol},
           (bit<32>)meta.reg.hash_size);
    }

    action hash_ip_proto_1() {
       hash(meta.hash.ip_proto_1,
           HashAlgorithm.crc32_custom,
           (bit<32>)0,
           {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.ipv4.protocol},
           (bit<32>)meta.reg.hash_size);
    }

    action hash_ip_proto_2() {
       hash(meta.hash.ip_proto_2,
           HashAlgorithm.crc32_custom,
           (bit<32>)0,
           {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.ipv4.protocol},
           (bit<32>)meta.reg.hash_size);
    }

    action hash_ip_src() {
       hash(meta.hash.ip_src,
           HashAlgorithm.crc32_custom,
           (bit<32>)0,
           {hdr.ipv4.src_addr},
           (bit<32>)meta.reg.hash_size);
    }

    action hash_ip_dst() {
       hash(meta.hash.ip_dst,
           HashAlgorithm.crc32_custom,
           (bit<32>)0,
           {hdr.ipv4.dst_addr},
           (bit<32>)meta.reg.hash_size);
    }

    action hash_ip_src_port_src() {
        hash(meta.hash.ip_src_port_src,
            HashAlgorithm.crc32_custom,
            (bit<32>)0,
            {hdr.ipv4.src_addr, meta.meta.l4_src_port},
            (bit<32>)meta.reg.hash_size);
    }

    action hash_ip_src_port_dst() {
        hash(meta.hash.ip_src_port_dst,
            HashAlgorithm.crc32_custom,
            (bit<32>)0,
            {hdr.ipv4.src_addr, meta.meta.l4_dst_port},
            (bit<32>)meta.reg.hash_size);
    }

    action hash_ip_dst_port_src() {
        hash(meta.hash.ip_dst_port_src,
            HashAlgorithm.crc32_custom,
            (bit<32>)0,
            {hdr.ipv4.dst_addr, meta.meta.l4_src_port},
            (bit<32>)meta.reg.hash_size);
    }

    action hash_ip_dst_port_dst() {
        hash(meta.hash.ip_dst_port_dst,
            HashAlgorithm.crc32_custom,
            (bit<32>)0,
            {hdr.ipv4.dst_addr, meta.meta.l4_dst_port},
            (bit<32>)meta.reg.hash_size);
    }

    action hash_ams_g_0() {
     hash(meta.hash.ams_g_0,
         HashAlgorithm.crc32_custom,
         (bit<32>)0,
         {hdr.ipv4.src_addr, hdr.ipv4.dst_addr},
         (bit<32>)2);
    }

    action hash_ams_g_1() {
     hash(meta.hash.ams_g_1,
         HashAlgorithm.crc32_custom,
         (bit<32>)0,
         {hdr.ipv4.src_addr, hdr.ipv4.dst_addr},
         (bit<32>)2);
    }

    action hash_ams_g_2() {
     hash(meta.hash.ams_g_2,
         HashAlgorithm.crc32_custom,
         (bit<32>)0,
         {hdr.ipv4.src_addr, hdr.ipv4.dst_addr},
         (bit<32>)2);
    }

    apply {

        hash_ip_0();
        hash_ip_1();
        hash_ip_2();

        hash_ip_src();
        hash_ip_dst();

        // The following hashes are only used in a single sketch variation.
        // This simple check verifies if their calculation is necessary.

        if (meta.reg.cm_ip_port_dst_cnt == 0 || meta.reg.cm_ip_port_dst_len == 0) {
            hash_ip_port_dst_0();
            hash_ip_port_dst_1();
            hash_ip_port_dst_2();
        }

        if (meta.reg.cm_ip_tcp_flags_cnt == 0 || meta.reg.cm_ip_tcp_flags_len == 0) {
            hash_ip_tcp_flags_0();
            hash_ip_tcp_flags_1();
            hash_ip_tcp_flags_2();
        }

        if (meta.reg.cm_ip_proto_cnt == 0 || meta.reg.cm_ip_proto_len == 0) {
            hash_ip_proto_0();
            hash_ip_proto_1();
            hash_ip_proto_2();
        }

        if (meta.reg.bm_ip_src_port_src == 0) hash_ip_src_port_src();
        if (meta.reg.bm_ip_src_port_dst == 0) hash_ip_src_port_dst();
        if (meta.reg.bm_ip_dst_port_src == 0) hash_ip_dst_port_src();
        if (meta.reg.bm_ip_dst_port_dst == 0) hash_ip_dst_port_dst();

        if (meta.reg.ams == 0) {
            hash_ams_g_0();
            hash_ams_g_1();
            hash_ams_g_2();
        }
    }
}
