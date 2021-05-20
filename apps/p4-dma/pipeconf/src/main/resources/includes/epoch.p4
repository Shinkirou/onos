// Control block responsible for checking if the epoch value stored in the current register position
// matches the value defined by the operator.
// If the values do not match, it resets the register position and updates the respective epoch value.

control c_epoch(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

    bit<32> current_reg_temp;

    action epoch_check_0() {
        reg_0.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_1() {
        reg_1.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_2() {
        reg_2.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_3() {
        reg_3.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_4() {
        reg_4.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_5() {
        reg_5.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_6() {
        reg_6.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_7() {
        reg_7.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_8() {
        reg_8.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_9() {
        reg_9.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_10() {
        reg_10.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_11() {
        reg_11.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_12() {
        reg_12.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_13() {
        reg_13.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_14() {
        reg_14.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_15() {
        reg_15.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_16() {
        reg_16.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_17() {
        reg_17.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_18() {
        reg_18.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_19() {
        reg_19.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_20() {
        reg_20.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_21() {
        reg_21.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_22() {
        reg_22.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_23() {
        reg_23.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_24() {
        reg_24.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }
    action epoch_check_25() {
        reg_25.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_26() {
        reg_26.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_27() {
        reg_27.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_28() {
        reg_28.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_29() {
        reg_29.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_30() {
        reg_30.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_31() {
        reg_31.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_32() {
        reg_32.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_33() {
        reg_33.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_34() {
        reg_34.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_35() {
        reg_35.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_36() {
        reg_36.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_37() {
        reg_37.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_38() {
        reg_38.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_39() {
        reg_39.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_40() {
        reg_40.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_41() {
        reg_41.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_42() {
        reg_42.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_43() {
        reg_43.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_44() {
        reg_44.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_45() {
        reg_45.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_46() {
        reg_46.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_47() {
        reg_47.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_48() {
        reg_48.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_49() {
        reg_49.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_50() {
        reg_50.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action epoch_check_51() {
        reg_51.read(meta.epoch.sketch_temp, meta.reg.current_index);
    }

    action change_index_epoch() {

        meta.epoch.sketch_temp = 0;

        // After resetting the register value, the epoch bit is also changed to the current one.
        meta.epoch.sketch_temp[31:31] = meta.epoch.current_epoch;
    }

    action current_reg() {
        current_reg_temp = meta.reg.current_reg;
    }

    table t_epoch_check {
        key = {
            current_reg_temp: exact;
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
            epoch_check_36;
            epoch_check_37;
            epoch_check_38;
            epoch_check_39;
            epoch_check_40;
            epoch_check_41;
            epoch_check_42;
            epoch_check_43;
            epoch_check_44;
            epoch_check_45;
            epoch_check_46;
            epoch_check_47;
            epoch_check_48;
            epoch_check_49;
            epoch_check_50;
            epoch_check_51;
        }
    }

    apply {

        // Check the current value stored in the register position, in order to retrieve its epoch value.
        current_reg();
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
