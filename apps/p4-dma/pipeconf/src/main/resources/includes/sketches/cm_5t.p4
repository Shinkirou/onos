control c_cm_5t(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

	c_set_reg() cm_5t_set_reg_0;
	c_set_reg() cm_5t_set_reg_1;
	c_set_reg() cm_5t_set_reg_2;
	c_set_reg() cm_5t_set_reg_final;
	c_epoch()	cm_5t_epoch_0;
	c_epoch()	cm_5t_epoch_1;
	c_epoch()	cm_5t_epoch_2;

	bit<32> current_register_temp;

	action hash_cm_5t_0() {
		hash(meta.cm_5t.hash_0, 
			HashAlgorithm.crc32_custom, 
			(bit<32>)0, 
			{hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.meta.l4_src_port, (bit<32>)meta.meta.l4_dst_port}, 
			(bit<32>)meta.reg.hash_size);
	}

	action hash_cm_5t_1() {
		hash(meta.cm_5t.hash_1, 
			HashAlgorithm.crc32_custom, 
			(bit<32>)0, 
			{hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.meta.l4_src_port, (bit<32>)meta.meta.l4_dst_port}, 
			(bit<32>)meta.reg.hash_size);
	}

	action hash_cm_5t_2() {
		hash(meta.cm_5t.hash_2, 
			HashAlgorithm.crc32_custom, 
			(bit<32>)0, 
			{hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.meta.l4_src_port, (bit<32>)meta.meta.l4_dst_port}, 
			(bit<32>)meta.reg.hash_size);
	}

	action current_register() {
		current_register_temp = meta.reg.current_register;
	}

	action cm_incr() {
		meta.epoch.sketch_temp = meta.epoch.sketch_temp + 1;
	}

	action cm_write_0() {
		register_0.write(meta.reg.current_index, meta.epoch.sketch_temp);
	}

	action cm_write_1() {
		register_1.write(meta.reg.current_index, meta.epoch.sketch_temp);
	}

	action cm_write_2() {
		register_2.write(meta.reg.current_index, meta.epoch.sketch_temp);
	}						

	action cm_write_3() {
		register_3.write(meta.reg.current_index, meta.epoch.sketch_temp);
	}

	action cm_write_4() {
		register_4.write(meta.reg.current_index, meta.epoch.sketch_temp);
	}

	action cm_write_5() {
		register_5.write(meta.reg.current_index, meta.epoch.sketch_temp);
	}

	action cm_write_6() {
		register_6.write(meta.reg.current_index, meta.epoch.sketch_temp);
	}

	action cm_write_7() {
		register_7.write(meta.reg.current_index, meta.epoch.sketch_temp);
	}

	action cm_write_8() {
		register_8.write(meta.reg.current_index, meta.epoch.sketch_temp);
	}

	action cm_write_9() {
		register_9.write(meta.reg.current_index, meta.epoch.sketch_temp);
	}

	action cm_write_10() {
		register_10.write(meta.reg.current_index, meta.epoch.sketch_temp);
	}

	action cm_write_11() {
		register_11.write(meta.reg.current_index, meta.epoch.sketch_temp);
	}

	table t_cm_5t_0 {
		key = {
			current_register_temp: exact;
		}
		actions = {
			cm_write_0;
			cm_write_1;
			cm_write_2;
			cm_write_3;
			cm_write_4;
			cm_write_5;
			cm_write_6;
			cm_write_7;
			cm_write_8;
		}
	}

	table t_cm_5t_1 {
		key = {
			current_register_temp: exact;
		}		
		actions = {
			cm_write_1;
			cm_write_2;
			cm_write_3;
			cm_write_4;
			cm_write_5;
			cm_write_6;
			cm_write_7;
			cm_write_8;
			cm_write_9;
		}
	}

	table t_cm_5t_2 {
		key = {
			current_register_temp: exact;
		}		
		actions = {
			cm_write_2;
			cm_write_3;
			cm_write_4;
			cm_write_5;
			cm_write_6;
			cm_write_7;
			cm_write_8;
			cm_write_9;
			cm_write_10;
		}
	}

	table t_cm_5t_final {
		key = {
			current_register_temp: exact;
		}		
		actions = {
			cm_write_3;
			cm_write_4;
			cm_write_5;
			cm_write_6;
			cm_write_7;
			cm_write_8;
			cm_write_9;
			cm_write_10;
			cm_write_11;
		}
	}	

	apply {

		hash_cm_5t_0();
		hash_cm_5t_1();
		hash_cm_5t_2();

		// CM 5T Hash 0 - Counter 0.

		// Obtain the next hash value to be used.
		// This value will be translated by set_virtual_reg into the actual physical register and index.

		meta.reg.current_sketch_hash = meta.cm_5t.hash_0;

		cm_5t_set_reg_0.apply(hdr, meta, standard_metadata);		

		// After determining the register position, check if the epoch has changed.
		// The obtained sketch value after the check will be stored in meta.epoch.sketch_temp.
		cm_5t_epoch_0.apply(hdr, meta, standard_metadata);

		// Update the sketch value.

		cm_incr();

		current_register();

		t_cm_5t_0.apply();

		meta.cm_5t.sketch_0 = meta.epoch.sketch_temp;

		// CM 5T Hash 1 - Counter 1.

		meta.reg.current_sketch_hash = meta.cm_5t.hash_1;

		cm_5t_set_reg_1.apply(hdr, meta, standard_metadata);
		cm_5t_epoch_1.apply(hdr, meta, standard_metadata);

		cm_incr();

		current_register();

		t_cm_5t_1.apply();			

		meta.cm_5t.sketch_1 = meta.epoch.sketch_temp;

		// CM 5T Hash 2 - Counter 2.

		meta.reg.current_sketch_hash = meta.cm_5t.hash_2;

		cm_5t_set_reg_2.apply(hdr, meta, standard_metadata);
		cm_5t_epoch_2.apply(hdr, meta, standard_metadata);

		cm_incr();

		current_register();

		t_cm_5t_2.apply();			

		meta.cm_5t.sketch_2 = meta.epoch.sketch_temp;

		// CM 5T Final Value.

		cm_5t_set_reg_final.apply(hdr, meta, standard_metadata);
		
		// No need to apply an epoch check here, since all the cm values are already in the correct epoch
		// and one of them will be the final value.

		meta.epoch.sketch_temp = meta.cm_5t.sketch_0;

		if (meta.epoch.sketch_temp > meta.cm_5t.sketch_1) {
			meta.epoch.sketch_temp = meta.cm_5t.sketch_1;
		}
		
		if (meta.epoch.sketch_temp > meta.cm_5t.sketch_2) {
			meta.epoch.sketch_temp = meta.cm_5t.sketch_2;
		}

		current_register();

		t_cm_5t_final.apply();		
	}
}