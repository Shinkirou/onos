control c_bmSketch(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

    register<bit<32>>(REG_SKETCH_SIZE)  bm_0_register;
    // Bitmap register for the source address.
    register<bit<32>>(REG_SKETCH_SIZE)  bm_1_register;
    // Bitmap register for the destination address.
    register<bit<32>>(REG_SKETCH_SIZE)  bm_2_register;

    // Bitmap sketch actions

    action bm_0_hash() {
        hash(meta.bm_meta.bm_0_hash,
            HashAlgorithm.crc32_custom,
            (bit<32>)0,
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.meta.l4_src_port, (bit<32>)meta.meta.l4_dst_port},
            (bit<32>)REG_SKETCH_SIZE);
    }

    action bm_1_hash() {
        hash(meta.bm_meta.bm_1_hash, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.meta.l4_src_port}, 
            (bit<32>)REG_SKETCH_SIZE);
    }

    action bm_2_hash() {
        hash(meta.bm_meta.bm_2_hash, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.meta.l4_dst_port}, 
            (bit<32>)REG_SKETCH_SIZE);
    }          

    action bm_check_pair() {

        // Check the bitmap value for the (ip src, ip dst) pair
        bm_0_register.read(meta.bm_meta.bm_0_sketch, (bit<32>)meta.bm_meta.bm_0_hash);
    }

    action bm_new_pair() {
        
        bm_1_register.read(meta.bm_meta.bm_1_sketch, (bit<32>)meta.bm_meta.bm_1_hash);
        bm_2_register.read(meta.bm_meta.bm_2_sketch, (bit<32>)meta.bm_meta.bm_2_hash);

        bm_0_register.write((bit<32>)meta.bm_meta.bm_0_hash, 1);
        bm_1_register.write((bit<32>)meta.bm_meta.bm_1_hash, meta.bm_meta.bm_1_sketch + 1);
        bm_2_register.write((bit<32>)meta.bm_meta.bm_2_hash, meta.bm_meta.bm_2_sketch + 1);
    }

    apply {

        bm_0_hash();
        bm_1_hash();
        bm_2_hash();                
             
        // Check the bitmap value for the (ip src, ip dst) pair.
        bm_check_pair();

        // If the value is 0, it means we have a new pair.
        // write the bitmap value on register 0 and increase the counter for the ip src on register1.
        if (meta.bm_meta.bm_0_sketch == 0) {
            bm_new_pair();
        }
    }
}
