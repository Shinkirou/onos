control c_cm_ip(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

	c_set_reg() cm_ip_set_reg_0;
	c_set_reg() cm_ip_set_reg_1;
	c_set_reg() cm_ip_set_reg_2;
	c_set_reg() cm_ip_set_reg_final;
	c_epoch()	cm_ip_epoch_0;
	c_epoch()	cm_ip_epoch_1;
	c_epoch()	cm_ip_epoch_2;

	bit<32> current_register_temp;	

	action hash_cm_ip_0() {
		hash(meta.cm_ip.hash_0, 
			HashAlgorithm.crc32_custom, 
			(bit<32>)0, 
			{hdr.ipv4.src_addr, hdr.ipv4.dst_addr}, 
			(bit<32>)meta.reg.hash_size);
	}

	action hash_cm_ip_1() {
		hash(meta.cm_ip.hash_1, 
			HashAlgorithm.crc32_custom, 
			(bit<32>)0, 
			{hdr.ipv4.src_addr, hdr.ipv4.dst_addr}, 
			(bit<32>)meta.reg.hash_size);
	}

	action hash_cm_ip_2() {
		hash(meta.cm_ip.hash_2, 
			HashAlgorithm.crc32_custom, 
			(bit<32>)0, 
			{hdr.ipv4.src_addr, hdr.ipv4.dst_addr}, 
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

	action cm_write_12() {
		register_12.write(meta.reg.current_index, meta.epoch.sketch_temp);
	}

	action cm_write_13() {
		register_13.write(meta.reg.current_index, meta.epoch.sketch_temp);
	}

	action cm_write_14() {
		register_14.write(meta.reg.current_index, meta.epoch.sketch_temp);
	}

	action cm_write_15() {
		register_15.write(meta.reg.current_index, meta.epoch.sketch_temp);
	}

	action cm_write_16() {
		register_16.write(meta.reg.current_index, meta.epoch.sketch_temp);
	}

	action cm_write_17() {
		register_17.write(meta.reg.current_index, meta.epoch.sketch_temp);
	}

	action cm_write_18() {
		register_18.write(meta.reg.current_index, meta.epoch.sketch_temp);
	}

	action cm_write_19() {
		register_19.write(meta.reg.current_index, meta.epoch.sketch_temp);
	}					

	table t_cm_ip_0 {
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
			cm_write_9;
			cm_write_10;
			cm_write_11;
			cm_write_12;
			cm_write_13;
			cm_write_14;
			cm_write_15;
			cm_write_16;
		}
	}

	table t_cm_ip_1 {
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
			cm_write_10;
			cm_write_11;
			cm_write_12;
			cm_write_13;
			cm_write_14;
			cm_write_15;
			cm_write_16;
			cm_write_17;
		}
	}

	table t_cm_ip_2 {
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
			cm_write_11;
			cm_write_12;
			cm_write_13;
			cm_write_14;
			cm_write_15;
			cm_write_16;
			cm_write_17;
			cm_write_18;
		}
	}

	table t_cm_ip_final {
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
			cm_write_12;
			cm_write_13;
			cm_write_14;
			cm_write_15;
			cm_write_16;
			cm_write_17;
			cm_write_18;
			cm_write_19;
		}
	}	

	apply {

		hash_cm_ip_0();
		hash_cm_ip_1();
		hash_cm_ip_2();

		// CM ip Hash 0 - Counter 0.

		// Obtain the next hash value to be used.
		// This value will be translated by set_virtual_reg into the actual physical register and index.

		meta.reg.current_sketch_hash = meta.cm_ip.hash_0;

		cm_ip_set_reg_0.apply(hdr, meta, standard_metadata);

		// After determining the register position, check if the epoch has changed.
		// The obtained sketch value after the check will be stored in meta.epoch.sketch_temp.
		cm_ip_epoch_0.apply(hdr, meta, standard_metadata);

		// Update the sketch value.

		cm_incr();

		current_register();

		t_cm_ip_0.apply();

		meta.cm_ip.sketch_0 = meta.epoch.sketch_temp;

		// CM ip Hash 1 - Counter 1.

		meta.reg.current_sketch_hash = meta.cm_ip.hash_1;

		cm_ip_set_reg_1.apply(hdr, meta, standard_metadata);
		cm_ip_epoch_1.apply(hdr, meta, standard_metadata);

		cm_incr();

		current_register();

		t_cm_ip_1.apply();			

		meta.cm_ip.sketch_1 = meta.epoch.sketch_temp;

		// CM ip Hash 2 - Counter 2.

		meta.reg.current_sketch_hash = meta.cm_ip.hash_2;

		cm_ip_set_reg_2.apply(hdr, meta, standard_metadata);
		cm_ip_epoch_2.apply(hdr, meta, standard_metadata);

		cm_incr();

		current_register();

		t_cm_ip_2.apply();			

		meta.cm_ip.sketch_2 = meta.epoch.sketch_temp;

		// CM ip Final Value.

		cm_ip_set_reg_final.apply(hdr, meta, standard_metadata);
		
		// No need to apply an epoch check here, since all the cm values are already in the correct epoch
		// and one of them will be the final value.

		meta.epoch.sketch_temp = meta.cm_ip.sketch_0;

		if (meta.epoch.sketch_temp > meta.cm_ip.sketch_1) {
			meta.epoch.sketch_temp = meta.cm_ip.sketch_1;
		}
		
		if (meta.epoch.sketch_temp > meta.cm_ip.sketch_2) {
			meta.epoch.sketch_temp = meta.cm_ip.sketch_2;
		}

		current_register();

		t_cm_ip_final.apply();		
	}
}