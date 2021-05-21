control c_cm_ip_port_dst_len(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

    c_set_reg() cm_ip_port_dst_len_set_reg_0;
    c_set_reg() cm_ip_port_dst_len_set_reg_1;
    c_set_reg() cm_ip_port_dst_len_set_reg_2;
    c_set_reg() cm_ip_port_dst_len_set_reg_final;

    c_sketch_read() cm_ip_port_dst_len_read_0;
    c_sketch_read() cm_ip_port_dst_len_read_1;
    c_sketch_read() cm_ip_port_dst_len_read_2;

    c_sketch_write() cm_ip_port_dst_len_write_0;
    c_sketch_write() cm_ip_port_dst_len_write_1;
    c_sketch_write() cm_ip_port_dst_len_write_2;
    c_sketch_write() cm_ip_port_dst_len_write_final;

    bit<32> current_reg_temp;

    action current_reg() {
        current_reg_temp = meta.reg.current_reg;
    }

    action cm_incr() {
        meta.reg.sketch_temp = meta.reg.sketch_temp + standard_metadata.packet_length;
    }

    apply {

        // CM Hash 0 - Counter 0.

        // Obtain the next hash value to be used.
        // This value will be translated by set_virtual_reg into the actual physical register and index.

        meta.reg.current_sketch_hash = meta.hash.ip_port_dst_0;
        cm_ip_port_dst_len_set_reg_0.apply(hdr, meta, standard_metadata);

        // After determining the register position, check if the epoch has changed.
        // The obtained sketch value after the check will be stored in meta.reg.sketch_temp.
        cm_ip_port_dst_len_read_0.apply(hdr, meta, standard_metadata);

        // Update the sketch value.

        cm_incr();
        current_reg();
        cm_ip_port_dst_len_write_0.apply(hdr, meta, standard_metadata);
        meta.cm_ip_port_dst_len.sketch_0 = meta.reg.sketch_temp;

        // CM Hash 1 - Counter 1.

        meta.reg.current_sketch_hash = meta.hash.ip_port_dst_1;

        cm_ip_port_dst_len_set_reg_1.apply(hdr, meta, standard_metadata);
        cm_ip_port_dst_len_read_1.apply(hdr, meta, standard_metadata);

        cm_incr();
        current_reg();
        cm_ip_port_dst_len_write_1.apply(hdr, meta, standard_metadata);
        meta.cm_ip_port_dst_len.sketch_1 = meta.reg.sketch_temp;

        // CM Hash 2 - Counter 2.

        meta.reg.current_sketch_hash = meta.hash.ip_port_dst_2;

        cm_ip_port_dst_len_set_reg_2.apply(hdr, meta, standard_metadata);
        cm_ip_port_dst_len_read_2.apply(hdr, meta, standard_metadata);

        cm_incr();
        current_reg();
        cm_ip_port_dst_len_write_2.apply(hdr, meta, standard_metadata);
        meta.cm_ip_port_dst_len.sketch_2 = meta.reg.sketch_temp;

        // CM Final Value.

        cm_ip_port_dst_len_set_reg_final.apply(hdr, meta, standard_metadata);

        // No need to apply an epoch check here, since all the cm values are already in the correct epoch
        // and one of them will be the final value.

        meta.cm_ip_port_dst_len.sketch_final = meta.cm_ip_port_dst_len.sketch_0;

        if (meta.cm_ip_port_dst_len.sketch_final > meta.cm_ip_port_dst_len.sketch_1) {
            meta.cm_ip_port_dst_len.sketch_final = meta.cm_ip_port_dst_len.sketch_1;
        }

        if (meta.cm_ip_port_dst_len.sketch_final > meta.cm_ip_port_dst_len.sketch_2) {
            meta.cm_ip_port_dst_len.sketch_final = meta.cm_ip_port_dst_len.sketch_2;
        }

        meta.reg.sketch_temp = meta.cm_ip_port_dst_len.sketch_final;
        current_reg();
        cm_ip_port_dst_len_write_final.apply(hdr, meta, standard_metadata);
    }
}