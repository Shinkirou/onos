control c_cm_ip_dst_port_dst(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

    c_set_reg() cm_ip_dst_port_dst_set_reg_0;
    c_set_reg() cm_ip_dst_port_dst_set_reg_1;
    c_set_reg() cm_ip_dst_port_dst_set_reg_2;
    c_set_reg() cm_ip_dst_port_dst_set_reg_final;

    c_epoch()   cm_ip_dst_port_dst_epoch_0;
    c_epoch()   cm_ip_dst_port_dst_epoch_1;
    c_epoch()   cm_ip_dst_port_dst_epoch_2;

    c_sketch_write() cm_ip_dst_port_dst_write_0;
    c_sketch_write() cm_ip_dst_port_dst_write_1;
    c_sketch_write() cm_ip_dst_port_dst_write_2;
    c_sketch_write() cm_ip_dst_port_dst_write_final;

    bit<32> current_register_temp;

    action hash_0() {
        hash(meta.cm_ip_dst_port_dst.hash_0,
            HashAlgorithm.crc32_custom,
            (bit<32>)0,
            {hdr.ipv4.dst_addr, hdr.tcp.dst_port},
            (bit<32>)meta.reg.hash_size);
    }

    action hash_1() {
        hash(meta.cm_ip_dst_port_dst.hash_1,
            HashAlgorithm.crc32_custom,
            (bit<32>)0,
            {hdr.ipv4.dst_addr, hdr.tcp.dst_port},
            (bit<32>)meta.reg.hash_size);
    }

    action hash_2() {
        hash(meta.cm_ip_dst_port_dst.hash_2,
            HashAlgorithm.crc32_custom,
            (bit<32>)0,
            {hdr.ipv4.dst_addr, hdr.tcp.dst_port},
            (bit<32>)meta.reg.hash_size);
    }

    action current_register() {
        current_register_temp = meta.reg.current_register;
    }

    action cm_incr() {
        meta.epoch.sketch_temp = meta.epoch.sketch_temp + 1;
    }

    apply {

        hash_0();
        hash_1();
        hash_2();

        // CM Hash 0 - Counter 0.

        // Obtain the next hash value to be used.
        // This value will be translated by set_virtual_reg into the actual physical register and index.

        meta.reg.current_sketch_hash = meta.cm_ip_dst_port_dst.hash_0;
        cm_ip_dst_port_dst_set_reg_0.apply(hdr, meta, standard_metadata);

        // After determining the register position, check if the epoch has changed.
        // The obtained sketch value after the check will be stored in meta.epoch.sketch_temp.
        cm_ip_dst_port_dst_epoch_0.apply(hdr, meta, standard_metadata);

        // Update the sketch value.

        cm_incr();
        current_register();
        cm_ip_dst_port_dst_write_0.apply(hdr, meta, standard_metadata);
        meta.cm_ip_dst_port_dst.sketch_0 = meta.epoch.sketch_temp;

        // CM Hash 1 - Counter 1.

        meta.reg.current_sketch_hash = meta.cm_ip_dst_port_dst.hash_1;

        cm_ip_dst_port_dst_set_reg_1.apply(hdr, meta, standard_metadata);
        cm_ip_dst_port_dst_epoch_1.apply(hdr, meta, standard_metadata);

        cm_incr();
        current_register();
        cm_ip_dst_port_dst_write_1.apply(hdr, meta, standard_metadata);
        meta.cm_ip_dst_port_dst.sketch_1 = meta.epoch.sketch_temp;

        // CM Hash 2 - Counter 2.

        meta.reg.current_sketch_hash = meta.cm_ip_dst_port_dst.hash_2;

        cm_ip_dst_port_dst_set_reg_2.apply(hdr, meta, standard_metadata);
        cm_ip_dst_port_dst_epoch_2.apply(hdr, meta, standard_metadata);

        cm_incr();
        current_register();
        cm_ip_dst_port_dst_write_2.apply(hdr, meta, standard_metadata);
        meta.cm_ip_dst_port_dst.sketch_2 = meta.epoch.sketch_temp;

        // CM Final Value.

        cm_ip_dst_port_dst_set_reg_final.apply(hdr, meta, standard_metadata);

        // No need to apply an epoch check here, since all the cm values are already in the correct epoch
        // and one of them will be the final value.

        meta.cm_ip_dst_port_dst.sketch_final = meta.cm_ip_dst_port_dst.sketch_0;

        if (meta.cm_ip_dst_port_dst.sketch_final > meta.cm_ip_dst_port_dst.sketch_1) {
            meta.cm_ip_dst_port_dst.sketch_final = meta.cm_ip_dst_port_dst.sketch_1;
        }

        if (meta.cm_ip_dst_port_dst.sketch_final > meta.cm_ip_dst_port_dst.sketch_2) {
            meta.cm_ip_dst_port_dst.sketch_final = meta.cm_ip_dst_port_dst.sketch_2;
        }

        meta.epoch.sketch_temp = meta.cm_ip_dst_port_dst.sketch_final;
        current_register();
        cm_ip_dst_port_dst_write_final.apply(hdr, meta, standard_metadata);
    }
}