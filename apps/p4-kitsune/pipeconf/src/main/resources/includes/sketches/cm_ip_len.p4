control c_cm_ip_len(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

    c_set_reg() cm_ip_len_set_reg_0;
    c_set_reg() cm_ip_len_set_reg_1;
    c_set_reg() cm_ip_len_set_reg_2;
    c_set_reg() cm_ip_len_set_reg_final;

    c_sketch_read() cm_ip_len_read_0;
    c_sketch_read() cm_ip_len_read_1;
    c_sketch_read() cm_ip_len_read_2;

    c_sketch_write() cm_ip_len_write_0;
    c_sketch_write() cm_ip_len_write_1;
    c_sketch_write() cm_ip_len_write_2;
    c_sketch_write() cm_ip_len_write_final;

    // Store the squared sum of the packet length values, for each flow.
    register<bit<64>>(REG_SIZE) reg_cm_ip_len_ss_0;
    register<bit<64>>(REG_SIZE) reg_cm_ip_len_ss_1;
    register<bit<64>>(REG_SIZE) reg_cm_ip_len_ss_2;
    register<bit<64>>(REG_SIZE) reg_cm_ip_len_ss_final;

    bit<32> current_reg_temp;
    bit<64> squared_sum;

    action current_reg() {
        current_reg_temp = meta.reg.current_reg;
    }

    action cm_incr() {
        // The sketch calculation is performed after we update the stored value with the calculated decay.
        meta.reg.sketch_temp = meta.reg.sketch_temp >> meta.decay.value;
        meta.reg.sketch_temp = meta.reg.sketch_temp + standard_metadata.packet_length;
    }

    apply {

        squared_sum = (bit<64>)standard_metadata.packet_length * (bit<64>)standard_metadata.packet_length;

        // CM Hash 0 - Counter 0.

        // Obtain the next hash value to be used.
        // This value will be translated by set_reg into the actual physical register and index.

        meta.reg.current_sketch_hash = meta.hash.ip_0;
        cm_ip_len_set_reg_0.apply(hdr, meta, standard_metadata);

        // After determining the register position, read the respective sketch value.
        // The obtained sketch value after the check will be stored in meta.reg.sketch_temp.
        cm_ip_len_read_0.apply(hdr, meta, standard_metadata);

        // Update the sketch value.

        cm_incr();
        current_reg();
        cm_ip_len_write_0.apply(hdr, meta, standard_metadata);
        meta.cm_ip_len.sketch_0 = meta.reg.sketch_temp;

        // Update the squared sum value.

        reg_cm_ip_len_ss_0.read(meta.cm_ip_len.ss_0, meta.reg.current_sketch_hash);
        // The sketch calculation is performed after we update the stored value with the calculated decay.
        meta.cm_ip_len.ss_0 = meta.cm_ip_len.ss_0 >> meta.decay.value;
        meta.cm_ip_len.ss_0 = meta.cm_ip_len.ss_0 + squared_sum;
        reg_cm_ip_len_ss_0.write(meta.reg.current_sketch_hash, meta.cm_ip_len.ss_0);

        // CM Hash 1 - Counter 1.

        meta.reg.current_sketch_hash = meta.hash.ip_1;

        cm_ip_len_set_reg_1.apply(hdr, meta, standard_metadata);
        cm_ip_len_read_1.apply(hdr, meta, standard_metadata);

        cm_incr();
        current_reg();
        cm_ip_len_write_1.apply(hdr, meta, standard_metadata);
        meta.cm_ip_len.sketch_1 = meta.reg.sketch_temp;

        reg_cm_ip_len_ss_1.read(meta.cm_ip_len.ss_1, meta.reg.current_sketch_hash);
        meta.cm_ip_len.ss_1 = meta.cm_ip_len.ss_1 >> meta.decay.value;
        meta.cm_ip_len.ss_1 = meta.cm_ip_len.ss_1 + squared_sum;
        reg_cm_ip_len_ss_1.write(meta.reg.current_sketch_hash, meta.cm_ip_len.ss_1);

        // CM Hash 2 - Counter 2.

        meta.reg.current_sketch_hash = meta.hash.ip_2;

        cm_ip_len_set_reg_2.apply(hdr, meta, standard_metadata);
        cm_ip_len_read_2.apply(hdr, meta, standard_metadata);

        cm_incr();
        current_reg();
        cm_ip_len_write_2.apply(hdr, meta, standard_metadata);
        meta.cm_ip_len.sketch_2 = meta.reg.sketch_temp;

        reg_cm_ip_len_ss_2.read(meta.cm_ip_len.ss_2, meta.reg.current_sketch_hash);
        meta.cm_ip_len.ss_2 = meta.cm_ip_len.ss_2 >> meta.decay.value;
        meta.cm_ip_len.ss_2 = meta.cm_ip_len.ss_2 + squared_sum;
        reg_cm_ip_len_ss_2.write(meta.reg.current_sketch_hash, meta.cm_ip_len.ss_2);

        // CM Final Value.

        cm_ip_len_set_reg_final.apply(hdr, meta, standard_metadata);

        meta.cm_ip_len.sketch_final = meta.cm_ip_len.sketch_0;

        if (meta.cm_ip_len.sketch_final > meta.cm_ip_len.sketch_1) {
            meta.cm_ip_len.sketch_final = meta.cm_ip_len.sketch_1;
        }

        if (meta.cm_ip_len.sketch_final > meta.cm_ip_len.sketch_2) {
            meta.cm_ip_len.sketch_final = meta.cm_ip_len.sketch_2;
        }

        meta.reg.sketch_temp = meta.cm_ip_len.sketch_final;
        current_reg();
        cm_ip_len_write_final.apply(hdr, meta, standard_metadata);

        // Squared sum final value.

        meta.cm_ip_len.ss_final = meta.cm_ip_len.ss_0;

        if (meta.cm_ip_len.ss_final > meta.cm_ip_len.ss_1) {
            meta.cm_ip_len.ss_final = meta.cm_ip_len.ss_1;
        }

        if (meta.cm_ip_len.ss_final > meta.cm_ip_len.ss_2) {
            meta.cm_ip_len.ss_final = meta.cm_ip_len.ss_2;
        }

         reg_cm_ip_len_ss_final.write(meta.reg.current_sketch_hash, meta.cm_ip_len.ss_final);
    }
}