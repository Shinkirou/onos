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

    bit<32> current_register_temp;

    action hash_mv_0() {
        hash(meta.mv.hash_mv_0,
            HashAlgorithm.crc32_custom,
            (bit<32>)0,
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr},
            (bit<32>)meta.reg.hash_size);
    }

    action current_register() {
        current_register_temp = meta.reg.current_register;
    }

    action mv_write_0() {
        register_0.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action mv_write_1() {
        register_1.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action mv_write_2() {
        register_2.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action mv_write_3() {
        register_3.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action mv_write_4() {
        register_4.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action mv_write_5() {
        register_5.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action mv_write_6() {
        register_6.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action mv_write_7() {
        register_7.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action mv_write_8() {
        register_8.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action mv_write_9() {
        register_9.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action mv_write_10() {
        register_10.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action mv_write_11() {
        register_11.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action mv_write_12() {
        register_12.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action mv_write_13() {
        register_13.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action mv_write_14() {
        register_14.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action mv_write_15() {
        register_15.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action mv_write_16() {
        register_16.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action mv_write_17() {
        register_17.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action mv_write_18() {
        register_18.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action mv_write_19() {
        register_19.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action mv_write_20() {
        register_20.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action mv_write_21() {
        register_21.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action mv_write_22() {
        register_22.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action mv_write_23() {
        register_23.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }


    table t_mv_0 {
        key = {
            current_register_temp: exact;
        }
        actions = {
            mv_write_0;
            mv_write_1;
            mv_write_2;
            mv_write_3;
            mv_write_4;
            mv_write_5;
            mv_write_6;
            mv_write_7;
            mv_write_8;
            mv_write_9;
            mv_write_10;
            mv_write_11;
            mv_write_12;
            mv_write_13;
            mv_write_14;
            mv_write_15;
            mv_write_16;
            mv_write_17;
            mv_write_18;
            mv_write_19;
            mv_write_20;
        }
    }

    table t_mv_1 {
        key = {
            current_register_temp: exact;
        }
        actions = {
            mv_write_0;
            mv_write_1;
            mv_write_2;
            mv_write_3;
            mv_write_4;
            mv_write_5;
            mv_write_6;
            mv_write_7;
            mv_write_8;
            mv_write_9;
            mv_write_10;
            mv_write_11;
            mv_write_12;
            mv_write_13;
            mv_write_14;
            mv_write_15;
            mv_write_16;
            mv_write_17;
            mv_write_18;
            mv_write_19;
            mv_write_20;
            mv_write_21;
        }
    }

    table t_mv_2 {
        key = {
            current_register_temp: exact;
        }
        actions = {
            mv_write_0;
            mv_write_1;
            mv_write_2;
            mv_write_3;
            mv_write_4;
            mv_write_5;
            mv_write_6;
            mv_write_7;
            mv_write_8;
            mv_write_9;
            mv_write_10;
            mv_write_11;
            mv_write_12;
            mv_write_13;
            mv_write_14;
            mv_write_15;
            mv_write_16;
            mv_write_17;
            mv_write_18;
            mv_write_19;
            mv_write_20;
            mv_write_21;
            mv_write_22;
        }
    }

    table t_mv_3 {
        key = {
            current_register_temp: exact;
        }
        actions = {
            mv_write_0;
            mv_write_1;
            mv_write_2;
            mv_write_3;
            mv_write_4;
            mv_write_5;
            mv_write_6;
            mv_write_7;
            mv_write_8;
            mv_write_9;
            mv_write_10;
            mv_write_11;
            mv_write_12;
            mv_write_13;
            mv_write_14;
            mv_write_15;
            mv_write_16;
            mv_write_17;
            mv_write_18;
            mv_write_19;
            mv_write_20;
            mv_write_21;
            mv_write_22;
            mv_write_23;
        }
    }

    apply {

        bit<32> register_key_0_temp;
        bit<32> register_key_1_temp;

        bit<32> check = 0;

        // Obtain the next hash value to be used.
        // This value will be translated by set_virtual_reg into the actual physical register and index.

        hash_mv_0();

        meta.reg.current_sketch_hash = meta.mv.hash_mv_0;

        mv_set_reg_0.apply(hdr, meta, standard_metadata);

        // After determining the register position, check if the epoch has changed.
        // The obtained sketch value after the check will be stored in meta.epoch.sketch_temp.

        mv_epoch_0.apply(hdr, meta, standard_metadata);

        meta.epoch.sketch_temp = meta.epoch.sketch_temp + 1;

        current_register();

        t_mv_0.apply();

        // Register Key 0

        mv_set_reg_1.apply(hdr, meta, standard_metadata);

        mv_epoch_1.apply(hdr, meta, standard_metadata);

        register_key_0_temp = meta.epoch.sketch_temp;

        // Register Key 1

        mv_set_reg_2.apply(hdr, meta, standard_metadata);

        mv_epoch_2.apply(hdr, meta, standard_metadata);

        register_key_1_temp = meta.epoch.sketch_temp;

        // Register Count

        mv_set_reg_3.apply(hdr, meta, standard_metadata);

        mv_epoch_3.apply(hdr, meta, standard_metadata);

        meta.mv.count_temp = meta.epoch.sketch_temp;

        if (meta.epoch.current_epoch == 1) {
            register_key_0_temp[31:31] = (bit<1>) 0;
            register_key_1_temp[31:31] = (bit<1>) 0;
        }

        // Concatenate both register keys to generate the complete key.
        meta.mv.key_temp = register_key_0_temp ++ register_key_1_temp;

        // If the input key is different from the key stored in the register AND the related count is 0,
        // then the current input key becomes the new candidate heavy flow.
        if (meta.mv.key_temp != hdr.ipv4.src_addr ++ hdr.ipv4.dst_addr && meta.mv.count_temp == 0) {

            check = 1;

            meta.epoch.sketch_temp = hdr.ipv4.src_addr;
            mv_set_reg_4.apply(hdr, meta, standard_metadata);
            current_register();
            t_mv_1.apply();

            meta.epoch.sketch_temp = hdr.ipv4.dst_addr;
            mv_set_reg_5.apply(hdr, meta, standard_metadata);
            current_register();
            t_mv_2.apply();
        }

        // If the current key matches the one stored in the register then we increment the count value.
        // Else (the case where the input is different and the count is not 0), we decrement the count value (meaning that the current candidate has lost a vote count).
        if (meta.mv.key_temp == hdr.ipv4.src_addr ++ hdr.ipv4.dst_addr || meta.mv.count_temp == 0) {
            meta.epoch.sketch_temp = meta.mv.count_temp + 1;
        } else {
            meta.epoch.sketch_temp = meta.mv.count_temp - 1;
        }

        if (check == 1) {
            mv_set_reg_6.apply(hdr, meta, standard_metadata);
            current_register();
        }

        t_mv_3.apply();
    }
}