control c_bm_ip_dst_port_dst(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

    c_set_reg() bm_ip_dst_port_dst_set_reg_0;
    c_set_reg() bm_ip_dst_port_dst_set_reg_1;
    c_set_reg() bm_ip_dst_port_dst_set_reg_2;

    c_epoch()   bm_ip_dst_port_dst_epoch_0;
    c_epoch()   bm_ip_dst_port_dst_epoch_1;
    c_epoch()   bm_ip_dst_port_dst_epoch_2;

    c_sketch_write() bm_ip_dst_port_dst_write_0;
    c_sketch_write() bm_ip_dst_port_dst_write_1;

    bit<32> current_register_temp;

    action hash_0() {
        hash(meta.bm_ip_dst_port_dst.hash_0,
            HashAlgorithm.crc32_custom,
            (bit<32>)0,
            {hdr.ipv4.dst_addr, meta.meta.l4_dst_port},
            (bit<32>)meta.reg.hash_size);
    }

    action hash_1() {
        hash(meta.bm_ip_dst_port_dst.hash_1,
            HashAlgorithm.crc32_custom,
            (bit<32>)0,
            {hdr.ipv4.dst_addr},
            (bit<32>)meta.reg.hash_size);
    }

    action current_register() {
            current_register_temp = meta.reg.current_register;
    }

    apply {

        hash_0();
        hash_1();

        // BM IP Dst Port Dst - Bitmap value.

        // Obtain the next hash value to be used.
        // This value will be translated by set_virtual_reg into the actual physical register and index.

        meta.reg.current_sketch_hash = meta.bm_ip_dst_port_dst.hash_0;

        bm_ip_dst_port_dst_set_reg_0.apply(hdr, meta, standard_metadata);

        // After determining the register position, check if the epoch has changed.
        // The obtained sketch value after the check will be stored in meta.epoch.sketch_temp.
        bm_ip_dst_port_dst_epoch_0.apply(hdr, meta, standard_metadata);

        // Check the bitmap value for the (ip dst, port dst) pair.
        // This value is retrieved in epoch().

        // If the value is 0, it means we have a new pair.
        // Flip the respective bitmap bit to 1 and increase the counter for the ip dst.

        if (meta.epoch.sketch_temp[0:0] == 0) {

            meta.epoch.sketch_temp[0:0] = 1;

            current_register();

            bm_ip_dst_port_dst_write_0.apply(hdr, meta, standard_metadata);

            meta.reg.current_sketch_hash = meta.bm_ip_dst_port_dst.hash_1;

            bm_ip_dst_port_dst_set_reg_1.apply(hdr, meta, standard_metadata);
            bm_ip_dst_port_dst_epoch_1.apply(hdr, meta, standard_metadata);

            meta.epoch.sketch_temp = meta.epoch.sketch_temp + 1;
            meta.bm_ip_dst_port_dst.sketch_1 = meta.epoch.sketch_temp;

            current_register();

            bm_ip_dst_port_dst_write_1.apply(hdr, meta, standard_metadata);
        
        }  else {
              
            meta.reg.current_sketch_hash = meta.bm_ip_dst_port_dst.hash_1;

            bm_ip_dst_port_dst_set_reg_2.apply(hdr, meta, standard_metadata);
            bm_ip_dst_port_dst_epoch_2.apply(hdr, meta, standard_metadata);

            meta.bm_ip_dst_port_dst.sketch_1 = meta.epoch.sketch_temp;        	
        }		
    }
}