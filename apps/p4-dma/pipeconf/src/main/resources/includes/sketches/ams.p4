control c_ams(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

    c_set_reg() ams_set_reg_0;
    c_set_reg() ams_set_reg_1;
    c_set_reg() ams_set_reg_2;
    c_set_reg() ams_set_reg_final;

    c_sketch_read() ams_read_0;
    c_sketch_read() ams_read_1;
    c_sketch_read() ams_read_2;

    c_sketch_write() ams_write_0;
    c_sketch_write() ams_write_1;
    c_sketch_write() ams_write_2;
    c_sketch_write() ams_write_final;

    register<bit<32>>(1) reg_sum_0;
    register<bit<32>>(1) reg_sum_1;
    register<bit<32>>(1) reg_sum_2;

    bit<32> current_reg_temp;

    action current_reg() {
        current_reg_temp = meta.reg.current_reg;
    }

    // The update is made using the metadata, instead of directly on the registers.
    action ams_update(bit<32> aux) {
        meta.reg.sketch_temp = meta.reg.sketch_temp + aux;
    }

    apply {

        // AMS Counter 0.

        // Obtain the next hash value to be used.
        // This value will be translated by set_virtual_reg into the actual physical register and index.

        meta.reg.current_sketch_hash = meta.hash.ip_0;

        ams_set_reg_0.apply(hdr, meta, standard_metadata);

        // After determining the register position, check if the epoch has changed.
        // The obtained sketch value after the check will be stored in meta.reg.sketch_temp.
        ams_read_0.apply(hdr, meta, standard_metadata);

        // Update the sketch value.

        if (meta.hash.ams_g_0 == 0) meta.hash.ams_g_0 = meta.hash.ams_g_0 - 1;

        ams_update(meta.hash.ams_g_0);

        // After performing the sketch update, we check the related sum value epoch,
        // before updating the sum value (removing the old sketch value from it first).

        reg_sum_0.read(meta.ams.sum_0, (bit<32>)0);

        // The epoch value corresponds to the most significant bit in the retrieved value.
        bit<1> index_epoch = meta.ams.sum_0[31:31];

        // If current_epoch doesn't match index_epoch, then the actual epoch has since changed.
        // The current register position must be reset.
        // Assume that the register value is 0 and update while also changing the cur_epoch bit.

        if (meta.reg.current_epoch != index_epoch) {
            meta.ams.sum_0 = 0;
            // After resetting the register value, the epoch bit is also changed to the current one.
            meta.ams.sum_0[31:31] = meta.reg.current_epoch;
        }

        meta.ams.sum_0 = meta.ams.sum_0
            - ((meta.reg.sketch_temp - meta.hash.ams_g_0) * (meta.reg.sketch_temp - meta.hash.ams_g_0))
            + ((meta.reg.sketch_temp) * (meta.reg.sketch_temp));

        reg_sum_0.write((bit<32>)0, meta.ams.sum_0);

        current_reg();

        ams_write_0.apply(hdr, meta, standard_metadata);

        // AMS Counter 1.

        meta.reg.current_sketch_hash = meta.hash.ip_1;

        ams_set_reg_1.apply(hdr, meta, standard_metadata);

        ams_read_1.apply(hdr, meta, standard_metadata);

        if (meta.hash.ams_g_1 == 0) meta.hash.ams_g_1 = meta.hash.ams_g_1 - 1;

        ams_update(meta.hash.ams_g_1);

        reg_sum_1.read(meta.ams.sum_1, (bit<32>)0);

        index_epoch = meta.ams.sum_1[31:31];

        if (meta.reg.current_epoch != index_epoch) {
            meta.ams.sum_1 = 0;
            meta.ams.sum_1[31:31] = meta.reg.current_epoch;
        }

        meta.ams.sum_1 = meta.ams.sum_1
            - ((meta.reg.sketch_temp - meta.hash.ams_g_1) * (meta.reg.sketch_temp - meta.hash.ams_g_1))
            + ((meta.reg.sketch_temp) * (meta.reg.sketch_temp));

        reg_sum_1.write((bit<32>)0, meta.ams.sum_1);

        current_reg();

        ams_write_1.apply(hdr, meta, standard_metadata);

        // AMS Counter 2.

        meta.reg.current_sketch_hash = meta.hash.ip_2;

        ams_set_reg_2.apply(hdr, meta, standard_metadata);

        ams_read_2.apply(hdr, meta, standard_metadata);

        if (meta.hash.ams_g_2 == 0) meta.hash.ams_g_2 = meta.hash.ams_g_2 - 1;

        ams_update(meta.hash.ams_g_2);

        reg_sum_2.read(meta.ams.sum_2, (bit<32>)0);

        index_epoch = meta.ams.sum_2[31:31];

        if (meta.reg.current_epoch != index_epoch) {
            meta.ams.sum_2 = 0;
            meta.ams.sum_2[31:31] = meta.reg.current_epoch;
        }

        meta.ams.sum_2 = meta.ams.sum_2
            - ((meta.reg.sketch_temp - meta.hash.ams_g_2) * (meta.reg.sketch_temp - meta.hash.ams_g_2))
            + ((meta.reg.sketch_temp) * (meta.reg.sketch_temp));

        reg_sum_2.write((bit<32>)0, meta.ams.sum_2);

        current_reg();

        ams_write_2.apply(hdr, meta, standard_metadata);

        // AMS Final Value.

        ams_set_reg_final.apply(hdr, meta, standard_metadata);

        // No need to apply an epoch check here, since all the ams sum values are already in the correct epoch
        // and one of them will be the final value.

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

        meta.reg.sketch_temp = meta.ams.sketch_final;

        current_reg();

        ams_write_final.apply(hdr, meta, standard_metadata);
    }
}