// Control block responsible for reading the value in the current register/position.

control c_sketch_read(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

    bit<32> current_reg_temp;

    action sketch_read_0() {
        reg_0.read(meta.reg.sketch_temp, meta.reg.current_index);
    }

    action sketch_read_1() {
        reg_1.read(meta.reg.sketch_temp, meta.reg.current_index);
    }

    action sketch_read_2() {
        reg_2.read(meta.reg.sketch_temp, meta.reg.current_index);
    }

    action sketch_read_3() {
        reg_3.read(meta.reg.sketch_temp, meta.reg.current_index);
    }

    action sketch_read_4() {
        reg_4.read(meta.reg.sketch_temp, meta.reg.current_index);
    }

    action sketch_read_5() {
        reg_5.read(meta.reg.sketch_temp, meta.reg.current_index);
    }

    action sketch_read_6() {
        reg_6.read(meta.reg.sketch_temp, meta.reg.current_index);
    }

    action sketch_read_7() {
        reg_7.read(meta.reg.sketch_temp, meta.reg.current_index);
    }

    action sketch_read_8() {
        reg_8.read(meta.reg.sketch_temp, meta.reg.current_index);
    }

    action sketch_read_9() {
        reg_9.read(meta.reg.sketch_temp, meta.reg.current_index);
    }

    action sketch_read_10() {
        reg_10.read(meta.reg.sketch_temp, meta.reg.current_index);
    }

    action sketch_read_11() {
        reg_11.read(meta.reg.sketch_temp, meta.reg.current_index);
    }

    action sketch_read_12() {
        reg_12.read(meta.reg.sketch_temp, meta.reg.current_index);
    }

    action sketch_read_13() {
        reg_13.read(meta.reg.sketch_temp, meta.reg.current_index);
    }

    action sketch_read_14() {
        reg_14.read(meta.reg.sketch_temp, meta.reg.current_index);
    }

    action sketch_read_15() {
        reg_15.read(meta.reg.sketch_temp, meta.reg.current_index);
    }

    action sketch_read_16() {
        reg_16.read(meta.reg.sketch_temp, meta.reg.current_index);
    }

    action sketch_read_17() {
        reg_17.read(meta.reg.sketch_temp, meta.reg.current_index);
    }

    action sketch_read_18() {
        reg_18.read(meta.reg.sketch_temp, meta.reg.current_index);
    }

    action sketch_read_19() {
        reg_19.read(meta.reg.sketch_temp, meta.reg.current_index);
    }

    action sketch_read_20() {
        reg_20.read(meta.reg.sketch_temp, meta.reg.current_index);
    }

    action sketch_read_21() {
        reg_21.read(meta.reg.sketch_temp, meta.reg.current_index);
    }

    action sketch_read_22() {
        reg_22.read(meta.reg.sketch_temp, meta.reg.current_index);
    }

    action sketch_read_23() {
        reg_23.read(meta.reg.sketch_temp, meta.reg.current_index);
    }

    action sketch_read_24() {
        reg_24.read(meta.reg.sketch_temp, meta.reg.current_index);
    }
    action sketch_read_25() {
        reg_25.read(meta.reg.sketch_temp, meta.reg.current_index);
    }

    action sketch_read_26() {
        reg_26.read(meta.reg.sketch_temp, meta.reg.current_index);
    }

    action sketch_read_27() {
        reg_27.read(meta.reg.sketch_temp, meta.reg.current_index);
    }

    action sketch_read_28() {
        reg_28.read(meta.reg.sketch_temp, meta.reg.current_index);
    }

    action sketch_read_29() {
        reg_29.read(meta.reg.sketch_temp, meta.reg.current_index);
    }

    action sketch_read_30() {
        reg_30.read(meta.reg.sketch_temp, meta.reg.current_index);
    }

    action sketch_read_31() {
        reg_31.read(meta.reg.sketch_temp, meta.reg.current_index);
    }

    action sketch_read_32() {
        reg_32.read(meta.reg.sketch_temp, meta.reg.current_index);
    }

    action sketch_read_33() {
        reg_33.read(meta.reg.sketch_temp, meta.reg.current_index);
    }

    action sketch_read_34() {
        reg_34.read(meta.reg.sketch_temp, meta.reg.current_index);
    }

    action sketch_read_35() {
        reg_35.read(meta.reg.sketch_temp, meta.reg.current_index);
    }

    action sketch_read_36() {
        reg_36.read(meta.reg.sketch_temp, meta.reg.current_index);
    }

    action sketch_read_37() {
        reg_37.read(meta.reg.sketch_temp, meta.reg.current_index);
    }

    action sketch_read_38() {
        reg_38.read(meta.reg.sketch_temp, meta.reg.current_index);
    }

    action sketch_read_39() {
        reg_39.read(meta.reg.sketch_temp, meta.reg.current_index);
    }

    action sketch_read_40() {
        reg_40.read(meta.reg.sketch_temp, meta.reg.current_index);
    }

    action sketch_read_41() {
        reg_41.read(meta.reg.sketch_temp, meta.reg.current_index);
    }

    action sketch_read_42() {
        reg_42.read(meta.reg.sketch_temp, meta.reg.current_index);
    }

    action sketch_read_43() {
        reg_43.read(meta.reg.sketch_temp, meta.reg.current_index);
    }

    action sketch_read_44() {
        reg_44.read(meta.reg.sketch_temp, meta.reg.current_index);
    }

    action sketch_read_45() {
        reg_45.read(meta.reg.sketch_temp, meta.reg.current_index);
    }

    action sketch_read_46() {
        reg_46.read(meta.reg.sketch_temp, meta.reg.current_index);
    }

    action sketch_read_47() {
        reg_47.read(meta.reg.sketch_temp, meta.reg.current_index);
    }

    action sketch_read_48() {
        reg_48.read(meta.reg.sketch_temp, meta.reg.current_index);
    }

    action sketch_read_49() {
        reg_49.read(meta.reg.sketch_temp, meta.reg.current_index);
    }

    action sketch_read_50() {
        reg_50.read(meta.reg.sketch_temp, meta.reg.current_index);
    }

    action sketch_read_51() {
        reg_51.read(meta.reg.sketch_temp, meta.reg.current_index);
    }

    action current_reg() {
        current_reg_temp = meta.reg.current_reg;
    }

    table t_sketch_read {
        key = {
            current_reg_temp: exact;
        }
        actions = {
            sketch_read_0;
            sketch_read_1;
            sketch_read_2;
            sketch_read_3;
            sketch_read_4;
            sketch_read_5;
            sketch_read_6;
            sketch_read_7;
            sketch_read_8;
            sketch_read_9;
            sketch_read_10;
            sketch_read_11;
            sketch_read_12;
            sketch_read_13;
            sketch_read_14;
            sketch_read_15;
            sketch_read_16;
            sketch_read_17;
            sketch_read_18;
            sketch_read_19;
            sketch_read_20;
            sketch_read_21;
            sketch_read_22;
            sketch_read_23;
            sketch_read_24;
            sketch_read_25;
            sketch_read_26;
            sketch_read_27;
            sketch_read_28;
            sketch_read_29;
            sketch_read_30;
            sketch_read_31;
            sketch_read_32;
            sketch_read_33;
            sketch_read_34;
            sketch_read_35;
            sketch_read_36;
            sketch_read_37;
            sketch_read_38;
            sketch_read_39;
            sketch_read_40;
            sketch_read_41;
            sketch_read_42;
            sketch_read_43;
            sketch_read_44;
            sketch_read_45;
            sketch_read_46;
            sketch_read_47;
            sketch_read_48;
            sketch_read_49;
            sketch_read_50;
            sketch_read_51;
        }
    }

    apply {

        // Read the value stored in the current register position.

        current_reg();
        t_sketch_read.apply();
    }
}
