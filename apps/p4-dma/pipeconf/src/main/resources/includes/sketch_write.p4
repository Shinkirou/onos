control c_sketch_write(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

    bit<32> current_register_temp;

    action sketch_write_0() {
        register_0.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action sketch_write_1() {
        register_1.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action sketch_write_2() {
        register_2.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action sketch_write_3() {
        register_3.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action sketch_write_4() {
        register_4.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action sketch_write_5() {
        register_5.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action sketch_write_6() {
        register_6.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action sketch_write_7() {
        register_7.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action sketch_write_8() {
        register_8.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action sketch_write_9() {
        register_9.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action sketch_write_10() {
        register_10.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action sketch_write_11() {
        register_11.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action sketch_write_12() {
        register_12.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action sketch_write_13() {
        register_13.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action sketch_write_14() {
        register_14.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action sketch_write_15() {
        register_15.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action sketch_write_16() {
        register_16.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action sketch_write_17() {
        register_17.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action sketch_write_18() {
        register_18.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action sketch_write_19() {
        register_19.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action sketch_write_20() {
        register_20.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action sketch_write_21() {
        register_21.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action sketch_write_22() {
        register_22.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action sketch_write_23() {
        register_23.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action sketch_write_24() {
        register_24.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action sketch_write_25() {
        register_25.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action sketch_write_26() {
        register_26.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }
    
    action sketch_write_27() {
        register_27.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }
    
    action sketch_write_28() {
        register_28.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }
    
    action sketch_write_29() {
        register_29.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action sketch_write_30() {
        register_30.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }
    
    action sketch_write_31() {
        register_31.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action sketch_write_32() {
        register_32.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }
    
    action sketch_write_33() {
        register_33.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }
    
    action sketch_write_34() {
        register_34.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }
    
    action sketch_write_35() {
        register_35.write(meta.reg.current_index, meta.epoch.sketch_temp);
    }

    action current_register() {
        current_register_temp = meta.reg.current_register;
    }

    table t_sketch_write {
        key = {
            current_register_temp: exact;
        }
        actions = {
            sketch_write_0;
            sketch_write_1;
            sketch_write_2;
            sketch_write_3;
            sketch_write_4;
            sketch_write_5;
            sketch_write_6;
            sketch_write_7;
            sketch_write_8;
            sketch_write_9;
            sketch_write_10;
            sketch_write_11;
            sketch_write_12;
            sketch_write_13;
            sketch_write_14;
            sketch_write_15;
            sketch_write_16;
            sketch_write_17;
            sketch_write_18;
            sketch_write_19;
            sketch_write_20;
            sketch_write_21;
            sketch_write_22;
            sketch_write_23;
            sketch_write_24;
            sketch_write_25;
            sketch_write_26;
            sketch_write_27;
            sketch_write_28;
            sketch_write_29;
            sketch_write_30;
            sketch_write_31;
            sketch_write_32;
            sketch_write_33;
            sketch_write_34;
            sketch_write_35;
        }
    }

    apply {

        // Write the current sketch value in the register defined by the operator in the table rules.
			
        current_register();
        t_sketch_write.apply();
    }
}
