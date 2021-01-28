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

    action epoch_check_12() {
        register_12.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_13() {
        register_13.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_14() {
        register_14.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_15() {
        register_15.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_16() {
        register_16.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_17() {
        register_17.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_18() {
        register_18.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_19() {
        register_19.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_20() {
        register_20.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_21() {
        register_21.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_22() {
        register_22.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_23() {
        register_23.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_24() {
        register_24.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }
    action epoch_check_25() {
        register_25.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_26() {
        register_26.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_27() {
        register_27.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_28() {
        register_28.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_29() {
        register_29.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_30() {
        register_30.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_31() {
        register_31.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_32() {
        register_32.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_33() {
        register_33.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_34() {
        register_34.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_35() {
        register_35.read(meta.epoch.sketch_temp, meta.reg.current_index);
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
            epoch_check_12;
            epoch_check_13;
            epoch_check_14;
            epoch_check_15;
            epoch_check_16;
            epoch_check_17;
            epoch_check_18;
            epoch_check_19;
            epoch_check_20;
            epoch_check_21;
            epoch_check_22;
            epoch_check_23;
            epoch_check_24;
            epoch_check_25;
            epoch_check_26;
            epoch_check_27;
            epoch_check_28;
            epoch_check_29;
            epoch_check_30;
            epoch_check_31;
            epoch_check_32;
            epoch_check_33;
            epoch_check_34;
            epoch_check_35;
        }
    }

    apply {

        // Check the current value stored in the register position, in order to retrieve its epoch value.
			
        current_register();
        t_epoch_check.apply();

        // The epoch value corresponds to the most significant bit in the retrieved value.
        bit<1> index_epoch = meta.epoch.sketch_temp[31:31];

        // If current_epoch doesn't match index_epoch, then the actual epoch has since changed.
        // The current register position must be reset.
        // Assume that the register value is 0 and update while also changing the cur_epoch bit.
        if (meta.epoch.current_epoch != index_epoch) {
            change_index_epoch();
        }
    }
}
