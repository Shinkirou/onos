control c_bm_ip_dst(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

    register<bit<32>>(REG_SKETCH_SIZE)  reg_bm_ip_dst_0;
    register<bit<32>>(REG_SKETCH_SIZE)  reg_bm_ip_dst_1;

    // Bitmap sketch actions

    action hash_0() {
        hash(meta.bm_ip_dst.hash_0,
            HashAlgorithm.crc32_custom,
            (bit<32>)0,
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr},
            (bit<32>)REG_SKETCH_SIZE);
    }

    action hash_1() {
        hash(meta.bm_ip_dst.hash_1,
            HashAlgorithm.crc32_custom,
            (bit<32>)0,
            {hdr.ipv4.dst_addr},
            (bit<32>)REG_SKETCH_SIZE);
    }

    action bm_check_pair() {
        reg_bm_ip_dst_0.read(meta.bm_ip_dst.sketch_0, (bit<32>)meta.bm_ip_dst.hash_0);
    }

    action bm_new_pair() {

        reg_bm_ip_dst_1.read(meta.bm_ip_dst.sketch_1, (bit<32>)meta.bm_ip_dst.hash_1);

        meta.bm_ip_dst.sketch_1 = meta.bm_ip_dst.sketch_1 + 1;

        reg_bm_ip_dst_0.write((bit<32>)meta.bm_ip_dst.hash_0, 1);
        reg_bm_ip_dst_1.write((bit<32>)meta.bm_ip_dst.hash_1, meta.bm_ip_dst.sketch_1);
    }

    apply {

        hash_0();
        hash_1();

        // Check the bitmap value for the (ip src, ip dst) pair.
        bm_check_pair();

        // If the value is 0, it means we have a new pair.
        // write the bitmap value on register 0 and increase the counter for the ip dst on reg 1.
        if (meta.bm_ip_dst.sketch_0 == 0) {
               bm_new_pair();
        }
    }
}
