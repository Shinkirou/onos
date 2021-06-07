control c_cm_ip_proto_cnt(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

    c_set_reg() cm_ip_proto_cnt_set_reg_0;
    c_set_reg() cm_ip_proto_cnt_set_reg_1;
    c_set_reg() cm_ip_proto_cnt_set_reg_2;
    c_set_reg() cm_ip_proto_cnt_set_reg_final;

    c_sketch_read() cm_ip_proto_cnt_read_0;
    c_sketch_read() cm_ip_proto_cnt_read_1;
    c_sketch_read() cm_ip_proto_cnt_read_2;

    c_sketch_write() cm_ip_proto_cnt_write_0;
    c_sketch_write() cm_ip_proto_cnt_write_1;
    c_sketch_write() cm_ip_proto_cnt_write_2;
    c_sketch_write() cm_ip_proto_cnt_write_final;

    bit<32> current_reg_temp;

    action current_reg() {
        current_reg_temp = meta.reg.current_reg;
    }

    action cm_incr() {
        // The sketch calculation is performed after we update the stored value with the calculated decay.
        meta.reg.sketch_temp = meta.reg.sketch_temp >> meta.decay.value;
        meta.reg.sketch_temp = meta.reg.sketch_temp + 1;
    }

    apply {

        // CM Hash 0 - Counter 0.

        // Obtain the next hash value to be used.
        // This value will be translated by set_reg into the actual physical register and index.

        meta.reg.current_sketch_hash = meta.hash.ip_proto_0;
        cm_ip_proto_cnt_set_reg_0.apply(hdr, meta, standard_metadata);

        // After determining the register position, read the respective sketch value.
        // The obtained sketch value after the check will be stored in meta.reg.sketch_temp.
        cm_ip_proto_cnt_read_0.apply(hdr, meta, standard_metadata);

        // Update the sketch value.

        cm_incr();
        current_reg();
        cm_ip_proto_cnt_write_0.apply(hdr, meta, standard_metadata);
        meta.cm_ip_proto_cnt.sketch_0 = meta.reg.sketch_temp;

        // CM Hash 1 - Counter 1.

        meta.reg.current_sketch_hash = meta.hash.ip_proto_1;

        cm_ip_proto_cnt_set_reg_1.apply(hdr, meta, standard_metadata);
        cm_ip_proto_cnt_read_1.apply(hdr, meta, standard_metadata);

        cm_incr();
        current_reg();
        cm_ip_proto_cnt_write_1.apply(hdr, meta, standard_metadata);
        meta.cm_ip_proto_cnt.sketch_1 = meta.reg.sketch_temp;

        // CM Hash 2 - Counter 2.

        meta.reg.current_sketch_hash = meta.hash.ip_proto_2;

        cm_ip_proto_cnt_set_reg_2.apply(hdr, meta, standard_metadata);
        cm_ip_proto_cnt_read_2.apply(hdr, meta, standard_metadata);

        cm_incr();
        current_reg();
        cm_ip_proto_cnt_write_2.apply(hdr, meta, standard_metadata);
        meta.cm_ip_proto_cnt.sketch_2 = meta.reg.sketch_temp;

        // CM Final Value.

        cm_ip_proto_cnt_set_reg_final.apply(hdr, meta, standard_metadata);

        meta.cm_ip_proto_cnt.sketch_final = meta.cm_ip_proto_cnt.sketch_0;

        if (meta.cm_ip_proto_cnt.sketch_final > meta.cm_ip_proto_cnt.sketch_1) {
            meta.cm_ip_proto_cnt.sketch_final = meta.cm_ip_proto_cnt.sketch_1;
        }

        if (meta.cm_ip_proto_cnt.sketch_final > meta.cm_ip_proto_cnt.sketch_2) {
            meta.cm_ip_proto_cnt.sketch_final = meta.cm_ip_proto_cnt.sketch_2;
        }

        meta.reg.sketch_temp = meta.cm_ip_proto_cnt.sketch_final;
        current_reg();
        cm_ip_proto_cnt_write_final.apply(hdr, meta, standard_metadata);
    }
}