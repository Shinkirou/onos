control c_cm(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

    register<bit<32>>(REG_SKETCH_SIZE)  reg_cm_0;
    register<bit<32>>(REG_SKETCH_SIZE)  reg_cm_1;
    register<bit<32>>(REG_SKETCH_SIZE)  reg_cm_2;
    register<bit<32>>(REG_SKETCH_SIZE)  reg_cm_final;

    action hash_0() {
        hash(meta.cm.hash_0,
            HashAlgorithm.crc32_custom,
            (bit<32>)0,
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr},
            (bit<32>)REG_SKETCH_SIZE);
    }

    action hash_1() {
        hash(meta.cm.hash_1,
            HashAlgorithm.crc32_custom,
            (bit<32>)0,
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr},
            (bit<32>)REG_SKETCH_SIZE);
    }

    action hash_2() {
        hash(meta.cm.hash_2,
            HashAlgorithm.crc32_custom,
            (bit<32>)0,
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr},
            (bit<32>)REG_SKETCH_SIZE);
    }

    action cm_incr() {

        reg_cm_0.read(meta.cm.sketch_0, (bit<32>)meta.cm.hash_0);
        reg_cm_1.read(meta.cm.sketch_1, (bit<32>)meta.cm.hash_1);
        reg_cm_2.read(meta.cm.sketch_2, (bit<32>)meta.cm.hash_2);

        // Increment is made using the metadata, instead of directly on the registers.
        // This allows us to perform the final value comparison on the apply{} block.

        meta.cm.sketch_0 = meta.cm.sketch_0 + 1;
        meta.cm.sketch_1 = meta.cm.sketch_1 + 1;
        meta.cm.sketch_2 = meta.cm.sketch_2 + 1;

        reg_cm_0.write((bit<32>)meta.cm.hash_0, meta.cm.sketch_0);
        reg_cm_1.write((bit<32>)meta.cm.hash_1, meta.cm.sketch_1);
        reg_cm_2.write((bit<32>)meta.cm.hash_2, meta.cm.sketch_2);
    }

    action cm_register_write() {
        reg_cm_final.write((bit<32>)meta.cm.hash_2, meta.cm.sketch_final);
    }

    apply {

        // Count-min sketch.
        hash_0();
        hash_1();
        hash_2();

        // Increment the value on all registers.
        cm_incr();

        // Compare the current value on all registers and identify the smallest.
        meta.cm.sketch_final = meta.cm.sketch_0;

        if (meta.cm.sketch_final > meta.cm.sketch_1) {
            meta.cm.sketch_final = meta.cm.sketch_1;
        }

        if (meta.cm.sketch_final > meta.cm.sketch_2) {
            meta.cm.sketch_final = meta.cm.sketch_2;
        }

        // Write the smallest value to the final count-min register.
        cm_register_write();
    }

}
