control c_sketch_write(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

    bit<32> current_reg_temp;

    action sketch_write_0() {
        reg_0.write(meta.reg.current_index, meta.reg.sketch_temp);
    }

    action sketch_write_1() {
        reg_1.write(meta.reg.current_index, meta.reg.sketch_temp);
    }

    action sketch_write_2() {
        reg_2.write(meta.reg.current_index, meta.reg.sketch_temp);
    }

    action sketch_write_3() {
        reg_3.write(meta.reg.current_index, meta.reg.sketch_temp);
    }

    action sketch_write_4() {
        reg_4.write(meta.reg.current_index, meta.reg.sketch_temp);
    }

    action sketch_write_5() {
        reg_5.write(meta.reg.current_index, meta.reg.sketch_temp);
    }

    action sketch_write_6() {
        reg_6.write(meta.reg.current_index, meta.reg.sketch_temp);
    }

    action sketch_write_7() {
        reg_7.write(meta.reg.current_index, meta.reg.sketch_temp);
    }

    action sketch_write_8() {
        reg_8.write(meta.reg.current_index, meta.reg.sketch_temp);
    }

    action sketch_write_9() {
        reg_9.write(meta.reg.current_index, meta.reg.sketch_temp);
    }

    action sketch_write_10() {
        reg_10.write(meta.reg.current_index, meta.reg.sketch_temp);
    }

    action sketch_write_11() {
        reg_11.write(meta.reg.current_index, meta.reg.sketch_temp);
    }

    action sketch_write_12() {
        reg_12.write(meta.reg.current_index, meta.reg.sketch_temp);
    }

    action sketch_write_13() {
        reg_13.write(meta.reg.current_index, meta.reg.sketch_temp);
    }

    action sketch_write_14() {
        reg_14.write(meta.reg.current_index, meta.reg.sketch_temp);
    }

    action sketch_write_15() {
        reg_15.write(meta.reg.current_index, meta.reg.sketch_temp);
    }

    action sketch_write_16() {
        reg_16.write(meta.reg.current_index, meta.reg.sketch_temp);
    }

    action sketch_write_17() {
        reg_17.write(meta.reg.current_index, meta.reg.sketch_temp);
    }

    action sketch_write_18() {
        reg_18.write(meta.reg.current_index, meta.reg.sketch_temp);
    }

    action sketch_write_19() {
        reg_19.write(meta.reg.current_index, meta.reg.sketch_temp);
    }

    action sketch_write_20() {
        reg_20.write(meta.reg.current_index, meta.reg.sketch_temp);
    }

    action sketch_write_21() {
        reg_21.write(meta.reg.current_index, meta.reg.sketch_temp);
    }

    action sketch_write_22() {
        reg_22.write(meta.reg.current_index, meta.reg.sketch_temp);
    }

    action sketch_write_23() {
        reg_23.write(meta.reg.current_index, meta.reg.sketch_temp);
    }

    action sketch_write_24() {
        reg_24.write(meta.reg.current_index, meta.reg.sketch_temp);
    }

    action sketch_write_25() {
        reg_25.write(meta.reg.current_index, meta.reg.sketch_temp);
    }

    action sketch_write_26() {
        reg_26.write(meta.reg.current_index, meta.reg.sketch_temp);
    }
    
    action sketch_write_27() {
        reg_27.write(meta.reg.current_index, meta.reg.sketch_temp);
    }
    
    action sketch_write_28() {
        reg_28.write(meta.reg.current_index, meta.reg.sketch_temp);
    }
    
    action sketch_write_29() {
        reg_29.write(meta.reg.current_index, meta.reg.sketch_temp);
    }

    action sketch_write_30() {
        reg_30.write(meta.reg.current_index, meta.reg.sketch_temp);
    }
    
    action sketch_write_31() {
        reg_31.write(meta.reg.current_index, meta.reg.sketch_temp);
    }

    action sketch_write_32() {
        reg_32.write(meta.reg.current_index, meta.reg.sketch_temp);
    }
    
    action sketch_write_33() {
        reg_33.write(meta.reg.current_index, meta.reg.sketch_temp);
    }
    
    action sketch_write_34() {
        reg_34.write(meta.reg.current_index, meta.reg.sketch_temp);
    }
    
    action sketch_write_35() {
        reg_35.write(meta.reg.current_index, meta.reg.sketch_temp);
    }

    action sketch_write_36() {
        reg_36.write(meta.reg.current_index, meta.reg.sketch_temp);
    }

    action sketch_write_37() {
        reg_37.write(meta.reg.current_index, meta.reg.sketch_temp);
    }

    action sketch_write_38() {
        reg_38.write(meta.reg.current_index, meta.reg.sketch_temp);
    }

    action sketch_write_39() {
        reg_39.write(meta.reg.current_index, meta.reg.sketch_temp);
    }

    action sketch_write_40() {
        reg_40.write(meta.reg.current_index, meta.reg.sketch_temp);
    }

    action sketch_write_41() {
        reg_41.write(meta.reg.current_index, meta.reg.sketch_temp);
    }

    action sketch_write_42() {
        reg_42.write(meta.reg.current_index, meta.reg.sketch_temp);
    }

    action sketch_write_43() {
        reg_43.write(meta.reg.current_index, meta.reg.sketch_temp);
    }

    action sketch_write_44() {
        reg_44.write(meta.reg.current_index, meta.reg.sketch_temp);
    }

    action sketch_write_45() {
        reg_45.write(meta.reg.current_index, meta.reg.sketch_temp);
    }

    action sketch_write_46() {
        reg_46.write(meta.reg.current_index, meta.reg.sketch_temp);
    }

    action sketch_write_47() {
        reg_47.write(meta.reg.current_index, meta.reg.sketch_temp);
    }

    action sketch_write_48() {
        reg_48.write(meta.reg.current_index, meta.reg.sketch_temp);
    }

    action sketch_write_49() {
        reg_49.write(meta.reg.current_index, meta.reg.sketch_temp);
    }

    action sketch_write_50() {
        reg_50.write(meta.reg.current_index, meta.reg.sketch_temp);
    }

    action sketch_write_51() {
        reg_51.write(meta.reg.current_index, meta.reg.sketch_temp);
    }

    action current_reg() {
        current_reg_temp = meta.reg.current_reg;
    }

    table t_sketch_write {
        key = {
            current_reg_temp: exact;
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
            sketch_write_36;
            sketch_write_37;
            sketch_write_38;
            sketch_write_39;
            sketch_write_40;
            sketch_write_41;
            sketch_write_42;
            sketch_write_43;
            sketch_write_44;
            sketch_write_45;
            sketch_write_46;
            sketch_write_47;
            sketch_write_48;
            sketch_write_49;
            sketch_write_50;
            sketch_write_51;
        }
    }

    apply {

        // Write the current sketch value in the register defined by the operator in the table rules.
			
        current_reg();
        t_sketch_write.apply();
    }
}
