control c_ams(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

    register<bit<32>>(REG_SKETCH_SIZE)  reg_ams_0;
    register<bit<32>>(REG_SKETCH_SIZE)  reg_ams_1;
    register<bit<32>>(REG_SKETCH_SIZE)  reg_ams_2;
    register<bit<32>>(1)                reg_ams_sum_0;
    register<bit<32>>(1)                reg_ams_sum_1;
    register<bit<32>>(1)                reg_ams_sum_2;
    register<bit<32>>(REG_SKETCH_SIZE)  reg_ams_final;

    action hash_0() {
        hash(meta.ams.hash_0,
            HashAlgorithm.crc32_custom,
            (bit<32>)0,
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr},
            (bit<32>)REG_SKETCH_SIZE);
    }

    action hash_1() {
        hash(meta.ams.hash_1,
            HashAlgorithm.crc32_custom,
            (bit<32>)0,
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr},
            (bit<32>)REG_SKETCH_SIZE);
    }

    action hash_2() {
        hash(meta.ams.hash_2,
            HashAlgorithm.crc32_custom,
            (bit<32>)0,
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr},
            (bit<32>)REG_SKETCH_SIZE);
    }

    // Second hash function that returns 0 or 1, corresponding to {-1, +1} from the original sketch.
    // These will be multiplied with the values to be added in the target counter.

    action hash_g_0() {
        hash(meta.ams.hash_g_0,
            HashAlgorithm.crc32_custom,
            (bit<32>)0,
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr},
            (bit<32>)2);
    }

    action hash_g_1() {
        hash(meta.ams.hash_g_1,
            HashAlgorithm.crc32_custom,
            (bit<32>)0,
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr},
            (bit<32>)2);
    }

    action hash_g_2() {
        hash(meta.ams.hash_g_2,
            HashAlgorithm.crc32_custom,
            (bit<32>)0,
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr},
            (bit<32>)2);
    }

    action ams_update(bit<32> aux_0, bit<32> aux_1, bit<32> aux_2) {

        reg_ams_0.read(meta.ams.sketch_0, (bit<32>)meta.ams.hash_0);
        reg_ams_1.read(meta.ams.sketch_1, (bit<32>)meta.ams.hash_1);
        reg_ams_2.read(meta.ams.sketch_2, (bit<32>)meta.ams.hash_2);

        reg_ams_sum_0.read(meta.ams.sum_0, (bit<32>)0);
        reg_ams_sum_1.read(meta.ams.sum_1, (bit<32>)1);
        reg_ams_sum_2.read(meta.ams.sum_2, (bit<32>)2);

        // The update is made using the metadata, instead of directly on the registers.
        // We also update the current sum value (removing the old sketch value from it first).

        meta.ams.sketch_0 = meta.ams.sketch_0 + aux_0;
        meta.ams.sum_0    = meta.ams.sum_0
                            - ((meta.ams.sketch_0 - aux_0) * (meta.ams.sketch_0 - aux_0))
                            + ((meta.ams.sketch_0) * (meta.ams.sketch_0));

        meta.ams.sketch_1 = meta.ams.sketch_1 + aux_1;
        meta.ams.sum_1    = meta.ams.sum_1
                            - ((meta.ams.sketch_1 - aux_1) * (meta.ams.sketch_1 - aux_1))
                            + ((meta.ams.sketch_1) * (meta.ams.sketch_1));

        meta.ams.sketch_2 = meta.ams.sketch_2 + aux_2;
        meta.ams.sum_2    = meta.ams.sum_2
                            - ((meta.ams.sketch_2 - aux_2) * (meta.ams.sketch_2 - aux_2))
                            + ((meta.ams.sketch_2) * (meta.ams.sketch_2));

        reg_ams_0.write((bit<32>)meta.ams.hash_0, meta.ams.sketch_0);
        reg_ams_1.write((bit<32>)meta.ams.hash_1, meta.ams.sketch_1);
        reg_ams_2.write((bit<32>)meta.ams.hash_2, meta.ams.sketch_2);

        reg_ams_sum_0.write((bit<32>)0, meta.ams.sum_0);
        reg_ams_sum_1.write((bit<32>)1, meta.ams.sum_1);
        reg_ams_sum_2.write((bit<32>)2, meta.ams.sum_2);
    }

    action ams_register_write() {
        reg_ams_final.write((bit<32>)meta.ams.hash_2, meta.ams.sketch_final);
    }

    apply {

        // AMS sketch.

        hash_0();
        hash_1();
        hash_2();

        hash_g_0();
        hash_g_1();
        hash_g_2();

        // If the hash output is 0, we change it to -1, to add/subtract in the subsequent update operation.

        if (meta.ams.hash_g_0 == 0) meta.ams.hash_g_0 = meta.ams.hash_g_0 - 1;
        if (meta.ams.hash_g_1 == 0) meta.ams.hash_g_0 = meta.ams.hash_g_0 - 1;
        if (meta.ams.hash_g_2 == 0) meta.ams.hash_g_0 = meta.ams.hash_g_0 - 1;

        // Increment or decrement the value on all registers.
        ams_update(meta.ams.hash_g_0, meta.ams.hash_g_1, meta.ams.hash_g_2);

        // Obtain the median value from all registers.

        if  ((meta.ams.sum_0 <= meta.ams.sum_1 && meta.ams.sum_0 <= meta.ams.sum_2) ||
             (meta.ams.sum_0 <= meta.ams.sum_1 && meta.ams.sum_0 >= meta.ams.sum_2) ||
             (meta.ams.sum_0 >= meta.ams.sum_1 && meta.ams.sum_0 <= meta.ams.sum_2) ||
             (meta.ams.sum_0 >= meta.ams.sum_1 && meta.ams.sum_0 >= meta.ams.sum_2)) {
                meta.ams.sketch_final = meta.ams.sum_0;
        }
        if  ((meta.ams.sum_1 <= meta.ams.sum_0 && meta.ams.sum_1 <= meta.ams.sum_2) ||
             (meta.ams.sum_1 <= meta.ams.sum_0 && meta.ams.sum_1 >= meta.ams.sum_2) ||
             (meta.ams.sum_1 >= meta.ams.sum_0 && meta.ams.sum_1 <= meta.ams.sum_2) ||
             (meta.ams.sum_1 >= meta.ams.sum_0 && meta.ams.sum_1 >= meta.ams.sum_2)) {
                meta.ams.sketch_final = meta.ams.sum_1;
        }
        else {
            meta.ams.sketch_final = meta.ams.sum_2;
        }

        ams_register_write();
    }

}
