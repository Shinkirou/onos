control c_ams(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

	c_set_reg() ams_set_reg_0;
	c_set_reg() ams_set_reg_1;
	c_set_reg() ams_set_reg_2;
	c_set_reg() ams_set_reg_final;
	c_epoch()	ams_epoch_0;
	c_epoch()	ams_epoch_1;
	c_epoch()	ams_epoch_2;

	register<bit<32>>(1) register_sum_0;
	register<bit<32>>(1) register_sum_1;
	register<bit<32>>(1) register_sum_2;

	bit<32> current_register_temp;

	action hash_ams_0() {
		hash(meta.ams.hash_0, 
			HashAlgorithm.crc32_custom, 
			(bit<32>)0, 
			{hdr.ipv4.src_addr, hdr.ipv4.dst_addr}, 
			(bit<32>)meta.reg.hash_size);
	}

	action hash_ams_1() {
		hash(meta.ams.hash_1, 
			HashAlgorithm.crc32_custom, 
			(bit<32>)0, 
			{hdr.ipv4.src_addr, hdr.ipv4.dst_addr}, 
			(bit<32>)meta.reg.hash_size);
	}

	action hash_ams_2() {
		hash(meta.ams.hash_2, 
			HashAlgorithm.crc32_custom, 
			(bit<32>)0, 
			{hdr.ipv4.src_addr, hdr.ipv4.dst_addr}, 
			(bit<32>)meta.reg.hash_size);
	}

	action hash_ams_g_0() {
		hash(meta.ams.hash_g_0, 
			HashAlgorithm.crc32_custom, 
			(bit<32>)0, 
			{hdr.ipv4.src_addr, hdr.ipv4.dst_addr},
			(bit<32>)2);        
	}

	action hash_ams_g_1() {
		hash(meta.ams.hash_g_1, 
			HashAlgorithm.crc32_custom, 
			(bit<32>)0, 
			{hdr.ipv4.src_addr, hdr.ipv4.dst_addr},
			(bit<32>)2);        
	}

	action hash_ams_g_2() {
		hash(meta.ams.hash_g_2, 
			HashAlgorithm.crc32_custom, 
			(bit<32>)0, 
			{hdr.ipv4.src_addr, hdr.ipv4.dst_addr},
			(bit<32>)2);        
	}

	action current_register() {
		current_register_temp = meta.reg.current_register;
	}

	// The update is made using the metadata, instead of directly on the registers.
	action ams_update(bit<32> aux) {
		meta.epoch.sketch_temp = meta.epoch.sketch_temp + aux;           
	}	

	action ams_write_0() {
		register_0.write(meta.reg.current_index, meta.epoch.sketch_temp);
	}

	action ams_write_1() {
		register_1.write(meta.reg.current_index, meta.epoch.sketch_temp);
	}

	action ams_write_2() {
		register_2.write(meta.reg.current_index, meta.epoch.sketch_temp);
	}						

	action ams_write_3() {
		register_3.write(meta.reg.current_index, meta.epoch.sketch_temp);
	}

	action ams_write_4() {
		register_4.write(meta.reg.current_index, meta.epoch.sketch_temp);
	}

	action ams_write_5() {
		register_5.write(meta.reg.current_index, meta.epoch.sketch_temp);
	}

	action ams_write_6() {
		register_6.write(meta.reg.current_index, meta.epoch.sketch_temp);
	}

	action ams_write_7() {
		register_7.write(meta.reg.current_index, meta.epoch.sketch_temp);
	}

	action ams_write_8() {
		register_8.write(meta.reg.current_index, meta.epoch.sketch_temp);
	}

	action ams_write_9() {
		register_9.write(meta.reg.current_index, meta.epoch.sketch_temp);
	}

	action ams_write_10() {
		register_10.write(meta.reg.current_index, meta.epoch.sketch_temp);
	}

	action ams_write_11() {
		register_11.write(meta.reg.current_index, meta.epoch.sketch_temp);
	}

	table t_ams_0 {
		key = {
			current_register_temp: exact;
		}
		actions = {
			ams_write_0;
			ams_write_1;
			ams_write_2;
			ams_write_3;
			ams_write_4;
			ams_write_5;
			ams_write_6;
			ams_write_7;
			ams_write_8;
		}
	}

	table t_ams_1 {
		key = {
			current_register_temp: exact;
		}		
		actions = {
			ams_write_1;
			ams_write_2;
			ams_write_3;
			ams_write_4;
			ams_write_5;
			ams_write_6;
			ams_write_7;
			ams_write_8;
			ams_write_9;
		}
	}

	table t_ams_2 {
		key = {
			current_register_temp: exact;
		}		
		actions = {
			ams_write_2;
			ams_write_3;
			ams_write_4;
			ams_write_5;
			ams_write_6;
			ams_write_7;
			ams_write_8;
			ams_write_9;
			ams_write_10;
		}
	}

	table t_ams_final {
		key = {
			current_register_temp: exact;
		}		
		actions = {
			ams_write_3;
			ams_write_4;
			ams_write_5;
			ams_write_6;
			ams_write_7;
			ams_write_8;
			ams_write_9;
			ams_write_10;
			ams_write_11;
		}
	}	

	apply {

		hash_ams_0();
		hash_ams_1();
		hash_ams_2();

		hash_ams_g_0();
		hash_ams_g_1();
		hash_ams_g_2();		

		// AMS Counter 0.

		// Obtain the next hash value to be used.
		// This value will be translated by set_virtual_reg into the actual physical register and index.

		meta.reg.current_sketch_hash = meta.ams.hash_0;

		ams_set_reg_0.apply(hdr, meta, standard_metadata);	

		// After determining the register position, check if the epoch has changed.
		// The obtained sketch value after the check will be stored in meta.epoch.sketch_temp.
		ams_epoch_0.apply(hdr, meta, standard_metadata);

		// Update the sketch value.

		if (meta.ams.hash_g_0 == 0) meta.ams.hash_g_0 = meta.ams.hash_g_0 - 1;

		ams_update(meta.ams.hash_g_0);

		// After performing the sketch update, we check the related sum value epoch,
		// before updating the sum value (removing the old sketch value from it first).

		register_sum_0.read(meta.ams.sum_0, (bit<32>)0);

		// The epoch value corresponds to the most significant bit in the retrieved value.
		bit<1> index_epoch = meta.ams.sum_0[31:31];

		// If current_epoch doesn't match index_epoch, then the actual epoch (defined by the operator) has since changed.
		// The current register position must be reset. Assume that the register value is 0 and update while also changing the cur_epoch bit.
		
		if (meta.epoch.current_epoch != index_epoch) {
			
			meta.ams.sum_0 = 0;

			// After resetting the register value, the epoch bit is also changed to the current one.
			meta.ams.sum_0[31:31] = meta.epoch.current_epoch;
		}

		meta.ams.sum_0 = meta.ams.sum_0 
							- ((meta.epoch.sketch_temp - meta.ams.hash_g_0) * (meta.epoch.sketch_temp - meta.ams.hash_g_0))
							+ ((meta.epoch.sketch_temp) * (meta.epoch.sketch_temp));		

		register_sum_0.write((bit<32>)0, meta.ams.sum_0);

		current_register();

		t_ams_0.apply();

		// AMS Counter 1.

		meta.reg.current_sketch_hash = meta.ams.hash_1;

		ams_set_reg_1.apply(hdr, meta, standard_metadata);	

		ams_epoch_1.apply(hdr, meta, standard_metadata);

		if (meta.ams.hash_g_1 == 0) meta.ams.hash_g_1 = meta.ams.hash_g_1 - 1;

		ams_update(meta.ams.hash_g_1);

		register_sum_1.read(meta.ams.sum_1, (bit<32>)0);

		index_epoch = meta.ams.sum_1[31:31];

		
		if (meta.epoch.current_epoch != index_epoch) {
			
			meta.ams.sum_1 = 0;
			meta.ams.sum_1[31:31] = meta.epoch.current_epoch;
		}

		meta.ams.sum_1 = meta.ams.sum_1 
							- ((meta.epoch.sketch_temp - meta.ams.hash_g_1) * (meta.epoch.sketch_temp - meta.ams.hash_g_1))
							+ ((meta.epoch.sketch_temp) * (meta.epoch.sketch_temp));		

		register_sum_1.write((bit<32>)0, meta.ams.sum_1);

		current_register();

		t_ams_1.apply();

		// AMS Counter 2.

		meta.reg.current_sketch_hash = meta.ams.hash_2;

		ams_set_reg_2.apply(hdr, meta, standard_metadata);	

		ams_epoch_2.apply(hdr, meta, standard_metadata);

		if (meta.ams.hash_g_2 == 0) meta.ams.hash_g_2 = meta.ams.hash_g_2 - 1;

		ams_update(meta.ams.hash_g_2);

		register_sum_2.read(meta.ams.sum_2, (bit<32>)0);

		index_epoch = meta.ams.sum_2[31:31];

		
		if (meta.epoch.current_epoch != index_epoch) {
			
			meta.ams.sum_2 = 0;
			meta.ams.sum_2[31:31] = meta.epoch.current_epoch;
		}

		meta.ams.sum_2 = meta.ams.sum_2 
							- ((meta.epoch.sketch_temp - meta.ams.hash_g_2) * (meta.epoch.sketch_temp - meta.ams.hash_g_2))
							+ ((meta.epoch.sketch_temp) * (meta.epoch.sketch_temp));		

		register_sum_2.write((bit<32>)0, meta.ams.sum_2);

		current_register();

		t_ams_2.apply();

		// AMS Final Value.

		ams_set_reg_final.apply(hdr, meta, standard_metadata);
		
		// No need to apply an epoch check here, since all the ams sum values are already in the correct epoch
		// and one of them will be the final value.

		// Obtain the median value from all registers.

		if  ((meta.ams.sum_0 <= meta.ams.sum_1 && meta.ams.sum_0 <= meta.ams.sum_2) ||
			 (meta.ams.sum_0 <= meta.ams.sum_1 && meta.ams.sum_0 >= meta.ams.sum_2) ||
			 (meta.ams.sum_0 >= meta.ams.sum_1 && meta.ams.sum_0 <= meta.ams.sum_2) ||
			 (meta.ams.sum_0 >= meta.ams.sum_1 && meta.ams.sum_0 >= meta.ams.sum_2)) {
				meta.epoch.sketch_temp = meta.ams.sum_0;
		} 
		if  ((meta.ams.sum_1 <= meta.ams.sum_0 && meta.ams.sum_1 <= meta.ams.sum_2) ||
			 (meta.ams.sum_1 <= meta.ams.sum_0 && meta.ams.sum_1 >= meta.ams.sum_2) ||
			 (meta.ams.sum_1 >= meta.ams.sum_0 && meta.ams.sum_1 <= meta.ams.sum_2) ||
			 (meta.ams.sum_1 >= meta.ams.sum_0 && meta.ams.sum_1 >= meta.ams.sum_2)) {
				meta.epoch.sketch_temp = meta.ams.sum_1;
		} 
		else {
			meta.epoch.sketch_temp = meta.ams.sum_2;
		}

		current_register();

		t_ams_final.apply();		
	}
}