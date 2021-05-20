control c_mv(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

    //define register arrays

    c_set_reg() mv_set_reg_0;
    c_set_reg() mv_set_reg_1;
    c_set_reg() mv_set_reg_2;
    c_set_reg() mv_set_reg_3;
    c_set_reg() mv_set_reg_4;
    c_set_reg() mv_set_reg_5;
    c_set_reg() mv_set_reg_6;

    c_epoch()	mv_epoch_0;
    c_epoch()	mv_epoch_1;
    c_epoch()	mv_epoch_2;
    c_epoch()	mv_epoch_3;

    c_sketch_write() mv_write_0;
    c_sketch_write() mv_write_1;
    c_sketch_write() mv_write_2;
    c_sketch_write() mv_write_3;

    bit<32> current_reg_temp;

    action current_reg() {
        current_reg_temp = meta.reg.current_reg;
    }

    apply {

        bit<32> reg_key_0_temp;
        bit<32> reg_key_1_temp;

        bit<32> check = 0;

        // Obtain the next hash value to be used.
        // This value will be translated by set_virtual_reg into the actual physical register and index.

        meta.reg.current_sketch_hash = meta.hash.ip_0;

        mv_set_reg_0.apply(hdr, meta, standard_metadata);

        // After determining the register position, check if the epoch has changed.
        // The obtained sketch value after the check will be stored in meta.epoch.sketch_temp.

        mv_epoch_0.apply(hdr, meta, standard_metadata);

        meta.epoch.sketch_temp = meta.epoch.sketch_temp + 1;

        current_reg();

        mv_write_0.apply(hdr, meta, standard_metadata);

        // Register Key 0

        mv_set_reg_1.apply(hdr, meta, standard_metadata);

        mv_epoch_1.apply(hdr, meta, standard_metadata);

        reg_key_0_temp = meta.epoch.sketch_temp;

        // Register Key 1

        mv_set_reg_2.apply(hdr, meta, standard_metadata);

        mv_epoch_2.apply(hdr, meta, standard_metadata);

        reg_key_1_temp = meta.epoch.sketch_temp;

        // Register Count

        mv_set_reg_3.apply(hdr, meta, standard_metadata);

        mv_epoch_3.apply(hdr, meta, standard_metadata);

        meta.mv.count_temp = meta.epoch.sketch_temp;

        if (meta.epoch.current_epoch == 1) {
            reg_key_0_temp[31:31] = (bit<1>) 0;
            reg_key_1_temp[31:31] = (bit<1>) 0;
        }

        // Concatenate both register keys to generate the complete key.
        meta.mv.key_temp = reg_key_0_temp ++ reg_key_1_temp;

        // If the input key is different from the key stored in the register AND the related count is 0,
        // then the current input key becomes the new candidate heavy flow.
        if (meta.mv.key_temp != hdr.ipv4.src_addr ++ hdr.ipv4.dst_addr && meta.mv.count_temp == 0) {

            check = 1;

            meta.epoch.sketch_temp = hdr.ipv4.src_addr;
            mv_set_reg_4.apply(hdr, meta, standard_metadata);
            current_reg();
            mv_write_1.apply(hdr, meta, standard_metadata);

            meta.epoch.sketch_temp = hdr.ipv4.dst_addr;
            mv_set_reg_5.apply(hdr, meta, standard_metadata);
            current_reg();
            mv_write_2.apply(hdr, meta, standard_metadata);
        }

        // If the current key matches the one stored in the register then we increment the count value.
        // Else (the case where the input is different and the count is not 0), we decrement the count value
        // (meaning that the current candidate has lost a vote count).
        if (meta.mv.key_temp == hdr.ipv4.src_addr ++ hdr.ipv4.dst_addr || meta.mv.count_temp == 0) {
            meta.epoch.sketch_temp = meta.mv.count_temp + 1;
        } else {
            meta.epoch.sketch_temp = meta.mv.count_temp - 1;
        }

        if (check == 1) {
            mv_set_reg_6.apply(hdr, meta, standard_metadata);
            current_reg();
        }

        mv_write_3.apply(hdr, meta, standard_metadata);
    }
}