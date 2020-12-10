control c_bm_ip_src_port_src(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

    c_set_reg() bm_ip_src_port_src_set_reg_0;
    c_set_reg() bm_ip_src_port_src_set_reg_1;
    c_set_reg() bm_ip_src_port_src_set_reg_2;
    c_epoch()   bm_ip_src_port_src_epoch_0;
    c_epoch()   bm_ip_src_port_src_epoch_1;
    c_epoch()   bm_ip_src_port_src_epoch_2;

    bit<32> current_register_temp;

    action hash_0() {
        hash(meta.bm_ip_src_port_src.hash_0,
            HashAlgorithm.crc32_custom,
            (bit<32>)0,
            {hdr.ipv4.src_addr, meta.meta.l4_src_port},
            (bit<32>)meta.reg.hash_size);
    }

    action hash_1() {
        hash(meta.bm_ip_src_port_src.hash_1,
            HashAlgorithm.crc32_custom,
            (bit<32>)0,
            {hdr.ipv4.src_addr},
            (bit<32>)meta.reg.hash_size);
    }

    action current_register() {
            current_register_temp = meta.reg.current_register;
    }

    action bm_write_0() {
        register_0.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action bm_write_1() {
        register_1.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action bm_write_2() {
        register_2.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action bm_write_3() {
        register_3.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action bm_write_4() {
        register_4.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action bm_write_5() {
        register_5.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action bm_write_6() {
        register_6.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action bm_write_7() {
        register_7.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action bm_write_8() {
        register_8.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action bm_write_9() {
        register_9.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action bm_write_10() {
       register_10.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action bm_write_11() {
        register_11.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action bm_write_12() {
        register_12.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action bm_write_13() {
        register_13.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action bm_write_14() {
        register_14.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action bm_write_15() {
        register_15.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action bm_write_16() {
        register_16.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action bm_write_17() {
        register_17.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action bm_write_18() {
        register_18.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action bm_write_19() {
        register_19.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action bm_write_20() {
        register_20.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action bm_write_21() {
        register_21.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action bm_write_22() {
        register_22.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action bm_write_23() {
        register_23.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    table t_bm_ip_src_port_src_0 {
        key = {
            current_register_temp: exact;
        }
        actions = {
            bm_write_0;
            bm_write_1;
            bm_write_2;
            bm_write_3;
            bm_write_4;
            bm_write_5;
            bm_write_6;
            bm_write_7;
            bm_write_8;
            bm_write_9;
            bm_write_10;
            bm_write_11;
            bm_write_12;
            bm_write_13;
            bm_write_14;
            bm_write_15;
            bm_write_16;
            bm_write_17;
            bm_write_18;
            bm_write_19;
            bm_write_20;
            bm_write_21;
            bm_write_22;
        }
    }

    table t_bm_ip_src_port_src_1 {
        key = {
            current_register_temp: exact;
        }
        actions = {
            bm_write_0;
            bm_write_1;
            bm_write_2;
            bm_write_3;
            bm_write_4;
            bm_write_5;
            bm_write_6;
            bm_write_7;
            bm_write_8;
            bm_write_9;
            bm_write_10;
            bm_write_11;
            bm_write_12;
            bm_write_13;
            bm_write_14;
            bm_write_15;
            bm_write_16;
            bm_write_17;
            bm_write_18;
            bm_write_19;
            bm_write_20;
            bm_write_21;
            bm_write_22;
            bm_write_23;
        }
    }

    apply {

        hash_0();
        hash_1();

        // BM IP Src Port Src - Bitmap value.

        // Obtain the next hash value to be used.
        // This value will be translated by set_virtual_reg into the actual physical register and index.

        meta.reg.current_sketch_hash = meta.bm_ip_src_port_src.hash_0;

        bm_ip_src_port_src_set_reg_0.apply(hdr, meta, standard_metadata);

        // After determining the register position, check if the epoch has changed.
        // The obtained sketch value after the check will be stored in meta.epoch.sketch_temp.
        bm_ip_src_port_src_epoch_0.apply(hdr, meta, standard_metadata);

        // Check the bitmap value for the (ip src, port src) pair.
        // This value is retrieved in epoch().

        // If the value is 0, it means we have a new pair.
        // Flip the respective bitmap bit to 1 and increase the counter for the ip src.

        if (meta.epoch.sketch_temp[0:0] == 0) {

            meta.epoch.sketch_temp[0:0] = 1;

            current_register();

            t_bm_ip_src_port_src_0.apply();

            meta.reg.current_sketch_hash = meta.bm_ip_src_port_src.hash_1;

            bm_ip_src_port_src_set_reg_1.apply(hdr, meta, standard_metadata);
            bm_ip_src_port_src_epoch_1.apply(hdr, meta, standard_metadata);

            meta.epoch.sketch_temp = meta.epoch.sketch_temp + 1;
            meta.bm_ip_src_port_src.sketch_1 = meta.epoch.sketch_temp;

            current_register();

            t_bm_ip_src_port_src_1.apply();
        
        }  else {
              
            meta.reg.current_sketch_hash = meta.bm_ip_src_port_src.hash_1;

            bm_ip_src_port_src_set_reg_2.apply(hdr, meta, standard_metadata);
            bm_ip_src_port_src_epoch_2.apply(hdr, meta, standard_metadata);

            meta.bm_ip_src_port_src.sketch_1 = meta.epoch.sketch_temp;        	
        }		
    }
}