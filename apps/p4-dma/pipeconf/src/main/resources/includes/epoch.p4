// Control block responsible for checking if the epoch value stored in the current register position
// matches the value defined by the operator.
// If the values do not match, it resets the register position and updates the respective epoch value.

control c_epoch(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

	bit<32> current_register_temp;

	action epoch_check_0() {
		register_0.read(meta.epoch.sketch_temp, meta.reg.current_index);
	}

	action epoch_check_1() {
		register_1.read(meta.epoch.sketch_temp, meta.reg.current_index);
	}

	action epoch_check_2() {
		register_2.read(meta.epoch.sketch_temp, meta.reg.current_index);
	}

	action epoch_check_3() {
		register_3.read(meta.epoch.sketch_temp, meta.reg.current_index);
	}

	action epoch_check_4() {
		register_4.read(meta.epoch.sketch_temp, meta.reg.current_index);
	}

	action epoch_check_5() {
		register_5.read(meta.epoch.sketch_temp, meta.reg.current_index);
	}

	action epoch_check_6() {
		register_6.read(meta.epoch.sketch_temp, meta.reg.current_index);
	}

	action epoch_check_7() {
		register_7.read(meta.epoch.sketch_temp, meta.reg.current_index);
	}

	action epoch_check_8() {
		register_8.read(meta.epoch.sketch_temp, meta.reg.current_index);
	}

	action epoch_check_9() {
		register_9.read(meta.epoch.sketch_temp, meta.reg.current_index);
	}

	action epoch_check_10() {
		register_10.read(meta.epoch.sketch_temp, meta.reg.current_index);
	}

	action epoch_check_11() {
		register_11.read(meta.epoch.sketch_temp, meta.reg.current_index);
	}											

	action change_index_epoch() {

		meta.epoch.sketch_temp = 0;

		// After resetting the register value, the epoch bit is also changed to the current one.
		meta.epoch.sketch_temp[31:31] = meta.epoch.current_epoch;
	}

	action current_register() {
		current_register_temp = meta.reg.current_register;
	}

	table t_epoch_check {
		key = {
			current_register_temp: exact;
		}
		actions = {
			epoch_check_0;
			epoch_check_1;
			epoch_check_2;
			epoch_check_3;
			epoch_check_4;
			epoch_check_5;
			epoch_check_6;
			epoch_check_7;
			epoch_check_8;
			epoch_check_9;
			epoch_check_10;
			epoch_check_11;
		}
	}	

	apply {

		// Check the current value stored in the register position, in order to retrieve its epoch value.
		
		current_register();
		t_epoch_check.apply();

		// The epoch value corresponds to the most significant bit in the retrieved value.
		bit<1> index_epoch = meta.epoch.sketch_temp[31:31];

		// If current_epoch doesn't match index_epoch, then the actual epoch (defined by the operator) has since changed.
		// The current register position must be reset. Assume that the register value is 0 and update while also changing the cur_epoch bit.
		if (meta.epoch.current_epoch != index_epoch) {
			change_index_epoch();
		}
	}
}
