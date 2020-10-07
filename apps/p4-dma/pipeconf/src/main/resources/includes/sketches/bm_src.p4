control c_bm_src(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

	c_set_reg() bm_src_set_reg_0;
	c_set_reg() bm_src_set_reg_1;
	c_set_reg() bm_src_set_reg_2;
	c_epoch()	bm_src_epoch_0;
	c_epoch()	bm_src_epoch_1;
	c_epoch() 	bm_src_epoch_2;

	bit<32> current_register_temp;	

    action hash_bm_src_0() {
        hash(meta.bm_src.hash_0,
            HashAlgorithm.crc32_custom,
            (bit<32>)0,
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.meta.l4_src_port, (bit<32>)meta.meta.l4_dst_port},
            (bit<32>)meta.reg.hash_size);
    }

    action hash_bm_src_1() {
        hash(meta.bm_src.hash_1, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.meta.l4_src_port}, 
            (bit<32>)meta.reg.hash_size);
    }	

	action current_register() {
		current_register_temp = meta.reg.current_register;
	}    

	action bm_write_bitmap_0() {
		register_0.write(meta.reg.current_index, meta.bm_src.sketch);
	}

	action bm_write_bitmap_1() {
		register_1.write(meta.reg.current_index, meta.bm_src.sketch);
	}

	action bm_write_bitmap_2() {
		register_2.write(meta.reg.current_index, meta.bm_src.sketch);
	}

	action bm_write_bitmap_3() {
		register_3.write(meta.reg.current_index, meta.bm_src.sketch);
	}

	action bm_write_bitmap_4() {
		register_4.write(meta.reg.current_index, meta.bm_src.sketch);
	}

	action bm_write_bitmap_5() {
		register_5.write(meta.reg.current_index, meta.bm_src.sketch);
	}

	action bm_write_bitmap_6() {
		register_6.write(meta.reg.current_index, meta.bm_src.sketch);
	}

	action bm_write_bitmap_7() {
		register_7.write(meta.reg.current_index, meta.bm_src.sketch);
	}

	action bm_write_bitmap_8() {
		register_8.write(meta.reg.current_index, meta.bm_src.sketch);
	}

	action bm_write_bitmap_9() {
		register_9.write(meta.reg.current_index, meta.bm_src.sketch);
	}

	action bm_write_bitmap_10() {
		register_10.write(meta.reg.current_index, meta.bm_src.sketch);
	}

	action bm_write_bitmap_11() {
		register_11.write(meta.reg.current_index, meta.bm_src.sketch);
	}

	action bm_write_bitmap_12() {
		register_12.write(meta.reg.current_index, meta.bm_src.sketch);
	}

	action bm_write_bitmap_13() {
		register_13.write(meta.reg.current_index, meta.bm_src.sketch);
	}

	action bm_write_bitmap_14() {
		register_14.write(meta.reg.current_index, meta.bm_src.sketch);
	}

	action bm_write_bitmap_15() {
		register_15.write(meta.reg.current_index, meta.bm_src.sketch);
	}

	action bm_write_bitmap_16() {
		register_16.write(meta.reg.current_index, meta.bm_src.sketch);
	}

	action bm_write_bitmap_17() {
		register_17.write(meta.reg.current_index, meta.bm_src.sketch);
	}

	action bm_write_bitmap_18() {
		register_18.write(meta.reg.current_index, meta.bm_src.sketch);
	}

	action bm_write_bitmap_19() {
		register_19.write(meta.reg.current_index, meta.bm_src.sketch);
	}								

	table t_bm_src_0 {
		key = {
			current_register_temp: exact;
		}		
		actions = {
			bm_write_bitmap_0;
			bm_write_bitmap_1;
			bm_write_bitmap_2;
			bm_write_bitmap_3;
			bm_write_bitmap_4;
			bm_write_bitmap_5;
			bm_write_bitmap_6;
			bm_write_bitmap_7;
			bm_write_bitmap_8;
			bm_write_bitmap_9;
			bm_write_bitmap_10;
			bm_write_bitmap_11;
			bm_write_bitmap_12;
			bm_write_bitmap_13;
			bm_write_bitmap_14;
			bm_write_bitmap_15;
			bm_write_bitmap_16;
			bm_write_bitmap_17;
			bm_write_bitmap_18;
		}
	}

	table t_bm_src_1 {
		key = {
			current_register_temp: exact;
		}		
		actions = {
			bm_write_bitmap_1;
			bm_write_bitmap_2;
			bm_write_bitmap_3;
			bm_write_bitmap_4;
			bm_write_bitmap_5;
			bm_write_bitmap_6;
			bm_write_bitmap_7;
			bm_write_bitmap_8;
			bm_write_bitmap_9;
			bm_write_bitmap_10;
			bm_write_bitmap_11;
			bm_write_bitmap_12;
			bm_write_bitmap_13;
			bm_write_bitmap_14;
			bm_write_bitmap_15;
			bm_write_bitmap_16;
			bm_write_bitmap_17;
			bm_write_bitmap_18;
			bm_write_bitmap_19;
		}
	}	

	apply {

		@atomic {

			hash_bm_src_0();
			hash_bm_src_1();

			// BM Src - Bitmap value.

			// Obtain the next hash value to be used.
			// This value will be translated by set_virtual_reg into the actual physical register and index.		

			meta.reg.current_sketch_hash = meta.bm_src.hash_0;

			bm_src_set_reg_0.apply(hdr, meta, standard_metadata);

			// After determining the register position, check if the epoch has changed.	
			// The obtained sketch value after the check will be stored in meta.epoch.sketch_temp. 
			bm_src_epoch_0.apply(hdr, meta, standard_metadata);

			// Check the bitmap value for the (ip src, ip dst) pair.
			// This value is retrieved in epoch().

	        // If the value is 0, it means we have a new pair.
	        // Flip the respective bitmap bit to 1 and increase the counter for the ip src.

	        if (meta.epoch.sketch_temp[0:0] == 0) {

	        	meta.bm_src.sketch 		= meta.epoch.sketch_temp;
	        	meta.bm_src.sketch[0:0] = 1;

	        	current_register();

				t_bm_src_0.apply();

				meta.reg.current_sketch_hash = meta.bm_src.hash_1;

				bm_src_set_reg_1.apply(hdr, meta, standard_metadata);
				bm_src_epoch_1.apply(hdr, meta, standard_metadata);

				meta.bm_src.sketch_final = meta.epoch.sketch_temp;
				
				meta.bm_src.sketch_final = meta.bm_src.sketch + 1;

				current_register();

				t_bm_src_1.apply();
	        
	        } else {

				meta.reg.current_sketch_hash = meta.bm_src.hash_1;

				bm_src_set_reg_2.apply(hdr, meta, standard_metadata);
				bm_src_epoch_2.apply(hdr, meta, standard_metadata);

				meta.bm_src.sketch_final = meta.epoch.sketch_temp;        	
	        }
        }		
	}
}