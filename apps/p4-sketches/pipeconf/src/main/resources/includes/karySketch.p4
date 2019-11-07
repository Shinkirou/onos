control c_karySketch(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

    // Register to store auxiliary values for the k-ary sketch.
    // Index 0 contains the current time interval value.
    // Index 1 contains the current alpha value for the EWMA forecast calculation.
    // Index 2 contains the current sum of all sketch values, needed for the estimate and estimate F2 calculation. 
    // Index 3, 4, 5, 6, 7 contain the current aux values for the estimate F2 summation block.
    // Index 8 contains the current estimate F2 value.
    register<bit<32>>(9) k_ary_aux_register;

    // K-ary registers that store the current sketch values for each flow.
    register<bit<32>>(REG_SKETCH_SIZE)  k_ary_0_sketch_register;
    register<bit<32>>(REG_SKETCH_SIZE)  k_ary_1_sketch_register;
    register<bit<32>>(REG_SKETCH_SIZE)  k_ary_2_sketch_register;
    register<bit<32>>(REG_SKETCH_SIZE)  k_ary_3_sketch_register;
    register<bit<32>>(REG_SKETCH_SIZE)  k_ary_4_sketch_register;

    // K-ary registers that store the current forecast values for each flow.
    register<bit<32>>(REG_SKETCH_SIZE)  k_ary_0_forecast_register;
    register<bit<32>>(REG_SKETCH_SIZE)  k_ary_1_forecast_register;
    register<bit<32>>(REG_SKETCH_SIZE)  k_ary_2_forecast_register;
    register<bit<32>>(REG_SKETCH_SIZE)  k_ary_3_forecast_register;
    register<bit<32>>(REG_SKETCH_SIZE)  k_ary_4_forecast_register;       

    // K-ary registers that store the forecast error values.
    register<bit<32>>(REG_SKETCH_SIZE)  k_ary_0_forecast_error_register;
    register<bit<32>>(REG_SKETCH_SIZE)  k_ary_1_forecast_error_register;
    register<bit<32>>(REG_SKETCH_SIZE)  k_ary_2_forecast_error_register;
    register<bit<32>>(REG_SKETCH_SIZE)  k_ary_3_forecast_error_register;
    register<bit<32>>(REG_SKETCH_SIZE)  k_ary_4_forecast_error_register;

	// TODO this definition was missing, I had to add it
	register<bit<32>>(REG_SKETCH_SIZE)  k_ary_register_estimate;

    // K-ary sketch actions

    action k_ary_0_hash() {
        hash(meta.k_ary_meta.k_ary_0_hash , 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr}, 
            (bit<32>)REG_SKETCH_SIZE);
    }

    action k_ary_1_hash() {
        hash(meta.k_ary_meta.k_ary_1_hash, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr}, 
            (bit<32>)REG_SKETCH_SIZE);
    }

    action k_ary_2_hash() {
        hash(meta.k_ary_meta.k_ary_2_hash, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr}, 
            (bit<32>)REG_SKETCH_SIZE);
    }

    action k_ary_3_hash() {
        hash(meta.k_ary_meta.k_ary_3_hash, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr}, 
            (bit<32>)REG_SKETCH_SIZE);
    }

    action k_ary_4_hash() {
        hash(meta.k_ary_meta.k_ary_4_hash, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr}, 
            (bit<32>)REG_SKETCH_SIZE);
    }

    // Ping hash.

    action ping_hash() {
        hash(meta.meta.ping_hash, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr}, 
            (bit<32>)REG_SKETCH_SIZE);
    }    

    action k_ary_sketch_incr() {

        // Retrieve the current sketch values.
        k_ary_0_sketch_register.read(meta.k_ary_meta.k_ary_0_sketch, (bit<32>)meta.k_ary_meta.k_ary_0_hash);
        k_ary_1_sketch_register.read(meta.k_ary_meta.k_ary_1_sketch, (bit<32>)meta.k_ary_meta.k_ary_1_hash);
        k_ary_2_sketch_register.read(meta.k_ary_meta.k_ary_2_sketch, (bit<32>)meta.k_ary_meta.k_ary_2_hash);
        k_ary_3_sketch_register.read(meta.k_ary_meta.k_ary_3_sketch, (bit<32>)meta.k_ary_meta.k_ary_3_hash);
        k_ary_4_sketch_register.read(meta.k_ary_meta.k_ary_4_sketch, (bit<32>)meta.k_ary_meta.k_ary_4_hash);

        // Update the old sketch metadata with the current values.

        meta.k_ary_meta.k_ary_0_sketch_old = meta.k_ary_meta.k_ary_0_sketch;
        meta.k_ary_meta.k_ary_1_sketch_old = meta.k_ary_meta.k_ary_1_sketch;
        meta.k_ary_meta.k_ary_2_sketch_old = meta.k_ary_meta.k_ary_2_sketch;
        meta.k_ary_meta.k_ary_3_sketch_old = meta.k_ary_meta.k_ary_3_sketch;
        meta.k_ary_meta.k_ary_4_sketch_old = meta.k_ary_meta.k_ary_4_sketch;

        // Increment the current values.
		// TODO: '++' is string concatenation, isn't it?
        //meta.k_ary_meta.k_ary_0_sketch++;
        //meta.k_ary_meta.k_ary_1_sketch++;
        //meta.k_ary_meta.k_ary_2_sketch++;
        //meta.k_ary_meta.k_ary_3_sketch++;
        //meta.k_ary_meta.k_ary_4_sketch++;

        meta.k_ary_meta.k_ary_0_sketch = meta.k_ary_meta.k_ary_0_sketch + 1;
        meta.k_ary_meta.k_ary_1_sketch = meta.k_ary_meta.k_ary_1_sketch + 1;
        meta.k_ary_meta.k_ary_2_sketch = meta.k_ary_meta.k_ary_2_sketch + 1;
        meta.k_ary_meta.k_ary_3_sketch = meta.k_ary_meta.k_ary_3_sketch + 1;
        meta.k_ary_meta.k_ary_4_sketch = meta.k_ary_meta.k_ary_4_sketch + 1;

        k_ary_0_sketch_register.write((bit<32>) meta.k_ary_meta.k_ary_0_hash, meta.k_ary_meta.k_ary_0_sketch);
        k_ary_1_sketch_register.write((bit<32>) meta.k_ary_meta.k_ary_1_hash, meta.k_ary_meta.k_ary_1_sketch);
        k_ary_2_sketch_register.write((bit<32>) meta.k_ary_meta.k_ary_2_hash, meta.k_ary_meta.k_ary_2_sketch);
        k_ary_3_sketch_register.write((bit<32>) meta.k_ary_meta.k_ary_3_hash, meta.k_ary_meta.k_ary_3_sketch);
        k_ary_4_sketch_register.write((bit<32>) meta.k_ary_meta.k_ary_4_hash, meta.k_ary_meta.k_ary_4_sketch);
    }

    action k_ary_forecast_interval_t_equals_2() {      

        // Update the forecast registers with the current values.
        k_ary_0_forecast_register.write((bit<32>)meta.k_ary_meta.k_ary_0_hash, meta.k_ary_meta.k_ary_0_sketch_old);
        k_ary_1_forecast_register.write((bit<32>)meta.k_ary_meta.k_ary_1_hash, meta.k_ary_meta.k_ary_1_sketch_old);
        k_ary_2_forecast_register.write((bit<32>)meta.k_ary_meta.k_ary_2_hash, meta.k_ary_meta.k_ary_2_sketch_old);
        k_ary_3_forecast_register.write((bit<32>)meta.k_ary_meta.k_ary_3_hash, meta.k_ary_meta.k_ary_3_sketch_old);
        k_ary_4_forecast_register.write((bit<32>)meta.k_ary_meta.k_ary_4_hash, meta.k_ary_meta.k_ary_4_sketch_old);
    }

    action k_ary_forecast_interval() {
        
        bit<32> alpha_temp;

        k_ary_aux_register.read(alpha_temp, (bit<32>)1);     

        // Retrieve the current forecast values.
        k_ary_0_forecast_register.read(meta.k_ary_meta.k_ary_0_forecast, (bit<32>)meta.k_ary_meta.k_ary_0_hash);
        k_ary_1_forecast_register.read(meta.k_ary_meta.k_ary_1_forecast, (bit<32>)meta.k_ary_meta.k_ary_1_hash);
        k_ary_2_forecast_register.read(meta.k_ary_meta.k_ary_2_forecast, (bit<32>)meta.k_ary_meta.k_ary_2_hash);
        k_ary_3_forecast_register.read(meta.k_ary_meta.k_ary_3_forecast, (bit<32>)meta.k_ary_meta.k_ary_3_hash);
        k_ary_4_forecast_register.read(meta.k_ary_meta.k_ary_4_forecast, (bit<32>)meta.k_ary_meta.k_ary_4_hash);

        // Calculate the current forecast.
        meta.k_ary_meta.k_ary_0_forecast = (alpha_temp * meta.k_ary_meta.k_ary_0_sketch_old) + ((1 - alpha_temp) * meta.k_ary_meta.k_ary_0_forecast);
        meta.k_ary_meta.k_ary_1_forecast = (alpha_temp * meta.k_ary_meta.k_ary_1_sketch_old) + ((1 - alpha_temp) * meta.k_ary_meta.k_ary_1_forecast);
        meta.k_ary_meta.k_ary_2_forecast = (alpha_temp * meta.k_ary_meta.k_ary_2_sketch_old) + ((1 - alpha_temp) * meta.k_ary_meta.k_ary_2_forecast);
        meta.k_ary_meta.k_ary_3_forecast = (alpha_temp * meta.k_ary_meta.k_ary_3_sketch_old) + ((1 - alpha_temp) * meta.k_ary_meta.k_ary_3_forecast);
        meta.k_ary_meta.k_ary_4_forecast = (alpha_temp * meta.k_ary_meta.k_ary_4_sketch_old) + ((1 - alpha_temp) * meta.k_ary_meta.k_ary_4_forecast);

        // Update the forecast registers with the current values.
        k_ary_0_forecast_register.write((bit<32>)meta.k_ary_meta.k_ary_0_hash, meta.k_ary_meta.k_ary_0_forecast);
        k_ary_1_forecast_register.write((bit<32>)meta.k_ary_meta.k_ary_1_hash, meta.k_ary_meta.k_ary_1_forecast);
        k_ary_2_forecast_register.write((bit<32>)meta.k_ary_meta.k_ary_2_hash, meta.k_ary_meta.k_ary_2_forecast);
        k_ary_3_forecast_register.write((bit<32>)meta.k_ary_meta.k_ary_3_hash, meta.k_ary_meta.k_ary_3_forecast);
        k_ary_4_forecast_register.write((bit<32>)meta.k_ary_meta.k_ary_4_hash, meta.k_ary_meta.k_ary_4_forecast);
    }

    action k_ary_forecast_error_sketch() {

        bit<32> sum_0_old_temp;
        bit<32> sum_1_old_temp;
        bit<32> sum_2_old_temp;
        bit<32> sum_3_old_temp;
        bit<32> sum_4_old_temp;

        // Retrieve the current k-ary sum value.
        k_ary_aux_register.read(meta.k_ary_meta.k_ary_sum, 2);

        // Retrieve the old forecast error values for the k-ary sum calculation.
        k_ary_0_forecast_error_register.read(sum_0_old_temp, (bit<32>)meta.k_ary_meta.k_ary_0_hash);
        k_ary_1_forecast_error_register.read(sum_1_old_temp, (bit<32>)meta.k_ary_meta.k_ary_1_hash);
        k_ary_2_forecast_error_register.read(sum_2_old_temp, (bit<32>)meta.k_ary_meta.k_ary_2_hash);
        k_ary_3_forecast_error_register.read(sum_3_old_temp, (bit<32>)meta.k_ary_meta.k_ary_3_hash);
        k_ary_4_forecast_error_register.read(sum_4_old_temp, (bit<32>)meta.k_ary_meta.k_ary_4_hash);      

        // Update the forecast error registers.
        // Delta between the observed sketch and current forecast. 

        meta.k_ary_meta.k_ary_0_error_sketch = meta.k_ary_meta.k_ary_0_sketch - meta.k_ary_meta.k_ary_0_forecast;
        meta.k_ary_meta.k_ary_1_error_sketch = meta.k_ary_meta.k_ary_1_sketch - meta.k_ary_meta.k_ary_1_forecast;
        meta.k_ary_meta.k_ary_2_error_sketch = meta.k_ary_meta.k_ary_2_sketch - meta.k_ary_meta.k_ary_2_forecast;
        meta.k_ary_meta.k_ary_3_error_sketch = meta.k_ary_meta.k_ary_3_sketch - meta.k_ary_meta.k_ary_3_forecast;
        meta.k_ary_meta.k_ary_4_error_sketch = meta.k_ary_meta.k_ary_4_sketch - meta.k_ary_meta.k_ary_4_forecast;

        k_ary_0_forecast_error_register.write((bit<32>)meta.k_ary_meta.k_ary_0_hash, meta.k_ary_meta.k_ary_0_error_sketch);
        k_ary_1_forecast_error_register.write((bit<32>)meta.k_ary_meta.k_ary_1_hash, meta.k_ary_meta.k_ary_1_error_sketch);
        k_ary_2_forecast_error_register.write((bit<32>)meta.k_ary_meta.k_ary_2_hash, meta.k_ary_meta.k_ary_2_error_sketch);
        k_ary_3_forecast_error_register.write((bit<32>)meta.k_ary_meta.k_ary_3_hash, meta.k_ary_meta.k_ary_3_error_sketch);
        k_ary_4_forecast_error_register.write((bit<32>)meta.k_ary_meta.k_ary_4_hash, meta.k_ary_meta.k_ary_4_error_sketch);

        // Calculate the current k-ary sum value.
        meta.k_ary_meta.k_ary_sum = meta.k_ary_meta.k_ary_sum - sum_0_old_temp + meta.k_ary_meta.k_ary_0_error_sketch
                                                              - sum_1_old_temp + meta.k_ary_meta.k_ary_1_error_sketch
                                                              - sum_2_old_temp + meta.k_ary_meta.k_ary_2_error_sketch
                                                              - sum_3_old_temp + meta.k_ary_meta.k_ary_3_error_sketch
                                                              - sum_4_old_temp + meta.k_ary_meta.k_ary_4_error_sketch;

        //Update the k-ary sum value.
        k_ary_aux_register.write(2, meta.k_ary_meta.k_ary_sum);                                                              

        // Retrieve the current auxiliary values for F2 (summation block) for each row.
        k_ary_aux_register.read(meta.k_ary_meta.k_ary_0_est_F2_sum, (bit<32>)3);
        k_ary_aux_register.read(meta.k_ary_meta.k_ary_1_est_F2_sum, (bit<32>)4); 
        k_ary_aux_register.read(meta.k_ary_meta.k_ary_2_est_F2_sum, (bit<32>)5); 
        k_ary_aux_register.read(meta.k_ary_meta.k_ary_3_est_F2_sum, (bit<32>)6); 
        k_ary_aux_register.read(meta.k_ary_meta.k_ary_4_est_F2_sum, (bit<32>)7); 

        // Increase the F2 auxiliary values (summation block) for each row.
        // In each case, if the value of the summation block is 0, the result will be the square product of the sketch value.
        // Otherwise, we subtract the previous iteration of the block, (sketch value -1 ) * (sketch value - 1)
        // and subsequently add the current (sketch value * sketch value) to the block. 

        if (meta.k_ary_meta.k_ary_0_est_F2_sum == 0) {
            meta.k_ary_meta.k_ary_0_est_F2_sum = meta.k_ary_meta.k_ary_0_error_sketch * meta.k_ary_meta.k_ary_0_error_sketch;
        } else {
            meta.k_ary_meta.k_ary_0_est_F2_sum = meta.k_ary_meta.k_ary_0_est_F2_sum - ((meta.k_ary_meta.k_ary_0_error_sketch - 1) * (meta.k_ary_meta.k_ary_0_error_sketch - 1));
            meta.k_ary_meta.k_ary_0_est_F2_sum = meta.k_ary_meta.k_ary_0_est_F2_sum + (meta.k_ary_meta.k_ary_0_error_sketch * meta.k_ary_meta.k_ary_0_error_sketch);
        }
        if (meta.k_ary_meta.k_ary_1_est_F2_sum == 0) {
            meta.k_ary_meta.k_ary_1_est_F2_sum = meta.k_ary_meta.k_ary_1_error_sketch * meta.k_ary_meta.k_ary_1_error_sketch;
        } else {
            meta.k_ary_meta.k_ary_1_est_F2_sum = meta.k_ary_meta.k_ary_1_est_F2_sum - ((meta.k_ary_meta.k_ary_1_error_sketch - 1) * (meta.k_ary_meta.k_ary_1_error_sketch - 1));
            meta.k_ary_meta.k_ary_1_est_F2_sum = meta.k_ary_meta.k_ary_1_est_F2_sum + (meta.k_ary_meta.k_ary_1_error_sketch * meta.k_ary_meta.k_ary_1_error_sketch);
        }
        if (meta.k_ary_meta.k_ary_2_est_F2_sum == 0) {
            meta.k_ary_meta.k_ary_2_est_F2_sum = meta.k_ary_meta.k_ary_2_error_sketch * meta.k_ary_meta.k_ary_2_error_sketch;
        } else {
            meta.k_ary_meta.k_ary_2_est_F2_sum = meta.k_ary_meta.k_ary_2_est_F2_sum - ((meta.k_ary_meta.k_ary_2_error_sketch - 1) * (meta.k_ary_meta.k_ary_2_error_sketch - 1));
            meta.k_ary_meta.k_ary_2_est_F2_sum = meta.k_ary_meta.k_ary_2_est_F2_sum + (meta.k_ary_meta.k_ary_2_error_sketch * meta.k_ary_meta.k_ary_2_error_sketch);
        }
        if (meta.k_ary_meta.k_ary_3_est_F2_sum == 0) {
            meta.k_ary_meta.k_ary_3_est_F2_sum = meta.k_ary_meta.k_ary_3_error_sketch * meta.k_ary_meta.k_ary_3_error_sketch;
        } else {
            meta.k_ary_meta.k_ary_3_est_F2_sum = meta.k_ary_meta.k_ary_3_est_F2_sum - ((meta.k_ary_meta.k_ary_3_error_sketch - 1) * (meta.k_ary_meta.k_ary_3_error_sketch - 1));
            meta.k_ary_meta.k_ary_3_est_F2_sum = meta.k_ary_meta.k_ary_3_est_F2_sum + (meta.k_ary_meta.k_ary_3_error_sketch * meta.k_ary_meta.k_ary_3_error_sketch);
        }
        if (meta.k_ary_meta.k_ary_4_est_F2_sum == 0) {
            meta.k_ary_meta.k_ary_4_est_F2_sum = meta.k_ary_meta.k_ary_4_error_sketch * meta.k_ary_meta.k_ary_4_error_sketch;
        } else {
            meta.k_ary_meta.k_ary_4_est_F2_sum = meta.k_ary_meta.k_ary_4_est_F2_sum - ((meta.k_ary_meta.k_ary_4_error_sketch - 1) * (meta.k_ary_meta.k_ary_4_error_sketch - 1));
            meta.k_ary_meta.k_ary_4_est_F2_sum = meta.k_ary_meta.k_ary_4_est_F2_sum + (meta.k_ary_meta.k_ary_4_error_sketch * meta.k_ary_meta.k_ary_4_error_sketch);
        }

        // Update the F2 auxiliary values (summation) for each row.

        k_ary_aux_register.write((bit<32>)3, meta.k_ary_meta.k_ary_0_est_F2_sum);
        k_ary_aux_register.write((bit<32>)4, meta.k_ary_meta.k_ary_1_est_F2_sum); 
        k_ary_aux_register.write((bit<32>)5, meta.k_ary_meta.k_ary_2_est_F2_sum); 
        k_ary_aux_register.write((bit<32>)6, meta.k_ary_meta.k_ary_3_est_F2_sum); 
        k_ary_aux_register.write((bit<32>)7, meta.k_ary_meta.k_ary_4_est_F2_sum);

    }

    action k_ary_median(bit<32> aux_0, bit<32> aux_1, bit<32> aux_2, bit<32> aux_3, bit<32> aux_4) {

        if  ((aux_0 <= aux_1 && aux_0 <= aux_2 && aux_0 >= aux_3 && aux_0 >= aux_4) ||
             (aux_0 <= aux_1 && aux_0 <= aux_3 && aux_0 >= aux_2 && aux_0 >= aux_4) ||
             (aux_0 <= aux_1 && aux_0 <= aux_4 && aux_0 >= aux_2 && aux_0 >= aux_3) ||
             (aux_0 <= aux_2 && aux_0 <= aux_3 && aux_0 >= aux_1 && aux_0 >= aux_4) ||
             (aux_0 <= aux_2 && aux_0 <= aux_4 && aux_0 >= aux_1 && aux_0 >= aux_3) ||
             (aux_0 <= aux_3 && aux_0 <= aux_4 && aux_0 >= aux_1 && aux_0 >= aux_2)) {
                meta.k_ary_meta.k_ary_median = aux_0;
        } 
        else if ((aux_1 <= aux_0 && aux_1 <= aux_2 && aux_1 >= aux_3 && aux_1 >= aux_4) ||
                 (aux_1 <= aux_0 && aux_1 <= aux_3 && aux_1 >= aux_2 && aux_1 >= aux_4) ||
                 (aux_1 <= aux_0 && aux_1 <= aux_4 && aux_1 >= aux_2 && aux_1 >= aux_3) ||
                 (aux_1 <= aux_2 && aux_1 <= aux_3 && aux_1 >= aux_0 && aux_1 >= aux_4) ||
                 (aux_1 <= aux_2 && aux_1 <= aux_4 && aux_1 >= aux_0 && aux_1 >= aux_3) ||
                 (aux_1 <= aux_3 && aux_1 <= aux_4 && aux_1 >= aux_0 && aux_1 >= aux_2)) {
                    meta.k_ary_meta.k_ary_median = aux_1;
        }
        else if ((aux_2 <= aux_1 && aux_2 <= aux_0 && aux_2 >= aux_3 && aux_2 >= aux_4) ||
                 (aux_2 <= aux_1 && aux_2 <= aux_3 && aux_2 >= aux_0 && aux_2 >= aux_4) ||
                 (aux_2 <= aux_1 && aux_2 <= aux_4 && aux_2 >= aux_0 && aux_2 >= aux_3) ||
                 (aux_2 <= aux_0 && aux_2 <= aux_3 && aux_2 >= aux_1 && aux_2 >= aux_4) ||
                 (aux_2 <= aux_0 && aux_2 <= aux_4 && aux_2 >= aux_1 && aux_2 >= aux_3) ||
                 (aux_2 <= aux_3 && aux_2 <= aux_4 && aux_2 >= aux_1 && aux_2 >= aux_0)) {
                    meta.k_ary_meta.k_ary_median = aux_2;
        }
        else if ((aux_3 <= aux_1 && aux_3 <= aux_2 && aux_3 >= aux_0 && aux_3 >= aux_4) ||
                 (aux_3 <= aux_1 && aux_3 <= aux_0 && aux_3 >= aux_2 && aux_3 >= aux_4) ||
                 (aux_3 <= aux_1 && aux_3 <= aux_4 && aux_3 >= aux_2 && aux_3 >= aux_0) ||
                 (aux_3 <= aux_2 && aux_3 <= aux_0 && aux_3 >= aux_1 && aux_3 >= aux_4) ||
                 (aux_3 <= aux_2 && aux_3 <= aux_4 && aux_3 >= aux_1 && aux_3 >= aux_0) ||
                 (aux_3 <= aux_0 && aux_3 <= aux_4 && aux_3 >= aux_1 && aux_3 >= aux_2)) {
                    meta.k_ary_meta.k_ary_median = aux_3;
        }
        else {
            meta.k_ary_meta.k_ary_median = aux_4;
        }
    }    

    action k_ary_estimate_row() {

        // Calculate the estimate for each row.
		// TODO here counting started from 1 to 5 in the rh exp, I had to change it 
        meta.k_ary_meta.est_row_0 = (meta.k_ary_meta.k_ary_0_error_sketch - (meta.k_ary_meta.k_ary_sum / REG_SKETCH_SIZE)) / (1 - (1 / REG_SKETCH_SIZE));
        meta.k_ary_meta.est_row_1 = (meta.k_ary_meta.k_ary_1_error_sketch - (meta.k_ary_meta.k_ary_sum / REG_SKETCH_SIZE)) / (1 - (1 / REG_SKETCH_SIZE));
        meta.k_ary_meta.est_row_2 = (meta.k_ary_meta.k_ary_2_error_sketch - (meta.k_ary_meta.k_ary_sum / REG_SKETCH_SIZE)) / (1 - (1 / REG_SKETCH_SIZE));
        meta.k_ary_meta.est_row_3 = (meta.k_ary_meta.k_ary_3_error_sketch - (meta.k_ary_meta.k_ary_sum / REG_SKETCH_SIZE)) / (1 - (1 / REG_SKETCH_SIZE));
        meta.k_ary_meta.est_row_4 = (meta.k_ary_meta.k_ary_4_error_sketch - (meta.k_ary_meta.k_ary_sum / REG_SKETCH_SIZE)) / (1 - (1 / REG_SKETCH_SIZE));
    }

    action k_ary_estimate_write() {
		// TODO the line below had names not valid for the current metadata, what was that? Sth left from a prev impl?
        //k_ary_register_estimate.write((bit<32>)meta.k_ary_meta.hash_0, meta.k_ary_meta.median);
        k_ary_register_estimate.write((bit<32>)meta.k_ary_meta.k_ary_0_hash, meta.k_ary_meta.k_ary_median);
    }

    action k_ary_estimate_F2_row() {

        // Retrieve the F2 auxiliary values for each row.

        k_ary_aux_register.read(meta.k_ary_meta.k_ary_0_est_F2_sum, (bit<32>)3);
        k_ary_aux_register.read(meta.k_ary_meta.k_ary_1_est_F2_sum, (bit<32>)4); 
        k_ary_aux_register.read(meta.k_ary_meta.k_ary_2_est_F2_sum, (bit<32>)5); 
        k_ary_aux_register.read(meta.k_ary_meta.k_ary_3_est_F2_sum, (bit<32>)6); 
        k_ary_aux_register.read(meta.k_ary_meta.k_ary_4_est_F2_sum, (bit<32>)7);        

        // Retrieve the current k-ary sum value.
        k_ary_aux_register.read(meta.k_ary_meta.k_ary_sum, 2);

        // Calculate the estimate F2 for each row.

        meta.k_ary_meta.k_ary_0_est_F2_sum = (REG_SKETCH_SIZE / (REG_SKETCH_SIZE - 1)) * (meta.k_ary_meta.k_ary_0_est_F2_sum) - (1 / (REG_SKETCH_SIZE - 1)) * (meta.k_ary_meta.k_ary_sum * meta.k_ary_meta.k_ary_sum);
        meta.k_ary_meta.k_ary_1_est_F2_sum = (REG_SKETCH_SIZE / (REG_SKETCH_SIZE - 1)) * (meta.k_ary_meta.k_ary_1_est_F2_sum) - (1 / (REG_SKETCH_SIZE - 1)) * (meta.k_ary_meta.k_ary_sum * meta.k_ary_meta.k_ary_sum);
        meta.k_ary_meta.k_ary_2_est_F2_sum = (REG_SKETCH_SIZE / (REG_SKETCH_SIZE - 1)) * (meta.k_ary_meta.k_ary_2_est_F2_sum) - (1 / (REG_SKETCH_SIZE - 1)) * (meta.k_ary_meta.k_ary_sum * meta.k_ary_meta.k_ary_sum);
        meta.k_ary_meta.k_ary_3_est_F2_sum = (REG_SKETCH_SIZE / (REG_SKETCH_SIZE - 1)) * (meta.k_ary_meta.k_ary_3_est_F2_sum) - (1 / (REG_SKETCH_SIZE - 1)) * (meta.k_ary_meta.k_ary_sum * meta.k_ary_meta.k_ary_sum);
        meta.k_ary_meta.k_ary_4_est_F2_sum = (REG_SKETCH_SIZE / (REG_SKETCH_SIZE - 1)) * (meta.k_ary_meta.k_ary_4_est_F2_sum) - (1 / (REG_SKETCH_SIZE - 1)) * (meta.k_ary_meta.k_ary_sum * meta.k_ary_meta.k_ary_sum);
    }

    action k_ary_estimate_F2_write() {
        // When this action is executed, the current median meta value is estimate F2.
        k_ary_aux_register.write((bit<32>)8, meta.k_ary_meta.k_ary_median);
    }             

	apply {

	    k_ary_0_hash();
	    k_ary_1_hash();
	    k_ary_2_hash();
	    k_ary_3_hash();
	    k_ary_4_hash();

	    k_ary_sketch_incr();

	    // Exponencially Weighted Moving Average (EWMA).
	    // If t_interval = 2, the current forecast value corresponds to the observed sketch of previous interval.
	    // Else, when i_interval > 2, the forecast value is the weighted average of the previous forecast 
	    // and the newly observed sample at time t - 1.

	    k_ary_aux_register.read(meta.k_ary_meta.t_interval, (bit<32>)0);

	    if (meta.k_ary_meta.t_interval == 2) {
	        k_ary_forecast_interval_t_equals_2();
	    } else {
	        k_ary_forecast_interval();
	    }

	    // The k-ary forecast error sketch is the delta between the observed sketch and the forecast sketch.
	    k_ary_forecast_error_sketch();

	    // K-ary sketch estimate.

	    k_ary_estimate_row();

	    k_ary_median(meta.k_ary_meta.est_row_0, 
	                 meta.k_ary_meta.est_row_1,
	                 meta.k_ary_meta.est_row_2,
	                 meta.k_ary_meta.est_row_3,
	                 meta.k_ary_meta.est_row_4);

	    k_ary_estimate_write();

        // Check if the current packet is part of a pingall.
        // Only run k-ary's estimate F2 if true.

        ping_hash();

        if ((bit<32>)meta.meta.ping_hash == PING_HASH) {

            // Estimate F2
            
            k_ary_estimate_F2_row();
            
            k_ary_median(meta.k_ary_meta.k_ary_0_est_F2_sum, 
                         meta.k_ary_meta.k_ary_1_est_F2_sum,
                         meta.k_ary_meta.k_ary_2_est_F2_sum,
                         meta.k_ary_meta.k_ary_3_est_F2_sum,
                         meta.k_ary_meta.k_ary_4_est_F2_sum);
            
            k_ary_estimate_F2_write();
        }	    
	}
}