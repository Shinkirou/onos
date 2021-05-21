control c_bm_ip_dst(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

    c_set_reg() bm_ip_dst_set_reg_0;
    c_set_reg() bm_ip_dst_set_reg_1;
    c_set_reg() bm_ip_dst_set_reg_2;

    c_sketch_read() bm_ip_dst_read_0;
    c_sketch_read() bm_ip_dst_read_1;
    c_sketch_read() bm_ip_dst_read_2;

    c_sketch_write() bm_ip_dst_write_0;
    c_sketch_write() bm_ip_dst_write_1;

    bit<32> current_reg_temp;

    action current_reg() {
            current_reg_temp = meta.reg.current_reg;
    }

    apply {

        // BM IP Dst - Bitmap value.

        // Obtain the next hash value to be used.
        // This value will be translated by set_virtual_reg into the actual physical register and index.

        meta.reg.current_sketch_hash = meta.hash.ip_0;

        bm_ip_dst_set_reg_0.apply(hdr, meta, standard_metadata);

        // After determining the register position, check if the epoch has changed.
        // The obtained sketch value after the check will be stored in meta.reg.sketch_temp.
        bm_ip_dst_read_0.apply(hdr, meta, standard_metadata);

        // Check the bitmap value for the (ip src, ip dst) pair.
        // This value is retrieved in epoch().

        // If the value is 0, it means we have a new pair.
        // Flip the respective bitmap bit to 1 and increase the counter for the ip dst.

        if (meta.reg.sketch_temp[0:0] == 0) {

            meta.reg.sketch_temp[0:0] = 1;

            current_reg();

            bm_ip_dst_write_0.apply(hdr, meta, standard_metadata);

            meta.reg.current_sketch_hash = meta.hash.ip_dst;

            bm_ip_dst_set_reg_1.apply(hdr, meta, standard_metadata);
            bm_ip_dst_read_1.apply(hdr, meta, standard_metadata);

            meta.reg.sketch_temp = meta.reg.sketch_temp + 1;
            meta.bm_ip_dst.sketch_1 = meta.reg.sketch_temp;

            current_reg();

            bm_ip_dst_write_1.apply(hdr, meta, standard_metadata);

        }  else {

            meta.reg.current_sketch_hash = meta.hash.ip_dst;

            bm_ip_dst_set_reg_2.apply(hdr, meta, standard_metadata);
            bm_ip_dst_read_2.apply(hdr, meta, standard_metadata);

            meta.bm_ip_dst.sketch_1 = meta.reg.sketch_temp;
        }
    }
}