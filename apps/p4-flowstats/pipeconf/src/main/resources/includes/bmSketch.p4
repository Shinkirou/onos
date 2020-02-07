control c_bmSketch(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

    register<bit<32>>(REG_SKETCH_SIZE)  register_0;
    // Bitmap register for the source address.
    register<bit<32>>(REG_SKETCH_SIZE)  register_1;
    // Bitmap register for the destination address.
    register<bit<32>>(REG_SKETCH_SIZE)  register_2;

    // Bitmap sketch actions

    action hash_0() {
        hash(meta.bm.hash_0,
            HashAlgorithm.crc32_custom,
            (bit<32>)0,
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.meta.l4_src_port, (bit<32>)meta.meta.l4_dst_port},
            (bit<32>)REG_SKETCH_SIZE);
    }

    action hash_1() {
        hash(meta.bm.hash_1, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.meta.l4_src_port}, 
            (bit<32>)REG_SKETCH_SIZE);
    }

    action hash_2() {
        hash(meta.bm.hash_2, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.meta.l4_dst_port}, 
            (bit<32>)REG_SKETCH_SIZE);
    }          

    action bm_check_pair() {

        // Check the bitmap value for the (ip src, ip dst) pair
        register_0.read(meta.bm.sketch_0, (bit<32>)meta.bm.hash_0);
    }

    action bm_new_pair() {
        
        register_1.read(meta.bm.sketch_1, (bit<32>)meta.bm.hash_1);
        register_2.read(meta.bm.sketch_2, (bit<32>)meta.bm.hash_2);

        meta.bm.sketch_1 = meta.bm.sketch_1 + 1;
        meta.bm.sketch_2 = meta.bm.sketch_2 + 1;

        register_0.write((bit<32>)meta.bm.hash_0, 1);
        register_1.write((bit<32>)meta.bm.hash_1, meta.bm.sketch_1);
        register_2.write((bit<32>)meta.bm.hash_2, meta.bm.sketch_2);
    }

    apply {

        hash_0();
        hash_1();
        hash_2();                
             
        // Check the bitmap value for the (ip src, ip dst) pair.
        bm_check_pair();

        // If the value is 0, it means we have a new pair.
        // write the bitmap value on register 0 and increase the counter for the ip src on register1.
        if (meta.bm.sketch_0 == 0) {
            bm_new_pair();
        }
    }
}
