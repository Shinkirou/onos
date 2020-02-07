control c_karySketch(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

    // Register to store auxiliary values for the k-ary sketch.
    // Index 0 contains the current time interval value.
    // Index 1 contains the current alpha value for the EWMA forecast calculation.
    // Index 2 contains the current sum of all sketch values, needed for the estimate and estimate F2 calculation. 
    // Index 3, 4, 5, 6, 7 contain the current aux values for the estimate F2 summation block.
    // Index 8 contains the current estimate F2 value.
    register<bit<32>>(9) register_aux;

    // K-ary registers that store the current sketch values for each flow.
    register<bit<32>>(REG_SKETCH_SIZE)  register_sketch_0;
    register<bit<32>>(REG_SKETCH_SIZE)  register_sketch_1;
    register<bit<32>>(REG_SKETCH_SIZE)  register_sketch_2;
    register<bit<32>>(REG_SKETCH_SIZE)  register_sketch_3;
    register<bit<32>>(REG_SKETCH_SIZE)  register_sketch_4;

    // K-ary registers that store the current forecast values for each flow.
    register<bit<32>>(REG_SKETCH_SIZE)  register_forecast_0;
    register<bit<32>>(REG_SKETCH_SIZE)  register_forecast_1;
    register<bit<32>>(REG_SKETCH_SIZE)  register_forecast_2;
    register<bit<32>>(REG_SKETCH_SIZE)  register_forecast_3;
    register<bit<32>>(REG_SKETCH_SIZE)  register_forecast_4;       

    // K-ary registers that store the forecast error values.
    register<bit<32>>(REG_SKETCH_SIZE)  register_error_0;
    register<bit<32>>(REG_SKETCH_SIZE)  register_error_1;
    register<bit<32>>(REG_SKETCH_SIZE)  register_error_2;
    register<bit<32>>(REG_SKETCH_SIZE)  register_error_3;
    register<bit<32>>(REG_SKETCH_SIZE)  register_error_4;

	register<bit<32>>(REG_SKETCH_SIZE)  register_estimate;

    // K-ary sketch actions

    action hash_0() {
        hash(meta.k_ary.hash_0 , 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr}, 
            (bit<32>)REG_SKETCH_SIZE);
    }

    action hash_1() {
        hash(meta.k_ary.hash_1, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr}, 
            (bit<32>)REG_SKETCH_SIZE);
    }

    action hash_2() {
        hash(meta.k_ary.hash_2, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr}, 
            (bit<32>)REG_SKETCH_SIZE);
    }

    action hash_3() {
        hash(meta.k_ary.hash_3, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr}, 
            (bit<32>)REG_SKETCH_SIZE);
    }

    action hash_4() {
        hash(meta.k_ary.hash_4, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr}, 
            (bit<32>)REG_SKETCH_SIZE);
    }

    // Ping hash.

    action hash_ping() {
        hash(meta.meta.hash_ping, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr}, 
            (bit<32>)REG_SKETCH_SIZE);
    }    

    action k_ary_sketch_incr() {

        // Retrieve the current sketch values.
        register_sketch_0.read(meta.k_ary.sketch_0, (bit<32>)meta.k_ary.hash_0);
        register_sketch_1.read(meta.k_ary.sketch_1, (bit<32>)meta.k_ary.hash_1);
        register_sketch_2.read(meta.k_ary.sketch_2, (bit<32>)meta.k_ary.hash_2);
        register_sketch_3.read(meta.k_ary.sketch_3, (bit<32>)meta.k_ary.hash_3);
        register_sketch_4.read(meta.k_ary.sketch_4, (bit<32>)meta.k_ary.hash_4);

        // Update the old sketch metadata with the current values.

        meta.k_ary.sketch_old_0 = meta.k_ary.sketch_0;
        meta.k_ary.sketch_old_1 = meta.k_ary.sketch_1;
        meta.k_ary.sketch_old_2 = meta.k_ary.sketch_2;
        meta.k_ary.sketch_old_3 = meta.k_ary.sketch_3;
        meta.k_ary.sketch_old_4 = meta.k_ary.sketch_4;

        // Increment the current values.

        meta.k_ary.sketch_0 = meta.k_ary.sketch_0 + 1;
        meta.k_ary.sketch_1 = meta.k_ary.sketch_1 + 1;
        meta.k_ary.sketch_2 = meta.k_ary.sketch_2 + 1;
        meta.k_ary.sketch_3 = meta.k_ary.sketch_3 + 1;
        meta.k_ary.sketch_4 = meta.k_ary.sketch_4 + 1;

        register_sketch_0.write((bit<32>) meta.k_ary.hash_0, meta.k_ary.sketch_0);
        register_sketch_1.write((bit<32>) meta.k_ary.hash_1, meta.k_ary.sketch_1);
        register_sketch_2.write((bit<32>) meta.k_ary.hash_2, meta.k_ary.sketch_2);
        register_sketch_3.write((bit<32>) meta.k_ary.hash_3, meta.k_ary.sketch_3);
        register_sketch_4.write((bit<32>) meta.k_ary.hash_4, meta.k_ary.sketch_4);
    }

    action k_ary_forecast_interval_t_equals_2() {      

        // Update the forecast registers with the current values.
        register_forecast_0.write((bit<32>)meta.k_ary.hash_0, meta.k_ary.sketch_old_0);
        register_forecast_1.write((bit<32>)meta.k_ary.hash_1, meta.k_ary.sketch_old_1);
        register_forecast_2.write((bit<32>)meta.k_ary.hash_2, meta.k_ary.sketch_old_2);
        register_forecast_3.write((bit<32>)meta.k_ary.hash_3, meta.k_ary.sketch_old_3);
        register_forecast_4.write((bit<32>)meta.k_ary.hash_4, meta.k_ary.sketch_old_4);
    }

    action k_ary_forecast_interval() {
        
        bit<32> temp_alpha;

        register_aux.read(temp_alpha, (bit<32>)1);     

        // Retrieve the current forecast values.
        register_forecast_0.read(meta.k_ary.forecast_0, (bit<32>)meta.k_ary.hash_0);
        register_forecast_1.read(meta.k_ary.forecast_1, (bit<32>)meta.k_ary.hash_1);
        register_forecast_2.read(meta.k_ary.forecast_2, (bit<32>)meta.k_ary.hash_2);
        register_forecast_3.read(meta.k_ary.forecast_3, (bit<32>)meta.k_ary.hash_3);
        register_forecast_4.read(meta.k_ary.forecast_4, (bit<32>)meta.k_ary.hash_4);

        // Calculate the current forecast.
        meta.k_ary.forecast_0 = (temp_alpha * meta.k_ary.sketch_old_0) + ((1 - temp_alpha) * meta.k_ary.forecast_0);
        meta.k_ary.forecast_1 = (temp_alpha * meta.k_ary.sketch_old_1) + ((1 - temp_alpha) * meta.k_ary.forecast_1);
        meta.k_ary.forecast_2 = (temp_alpha * meta.k_ary.sketch_old_2) + ((1 - temp_alpha) * meta.k_ary.forecast_2);
        meta.k_ary.forecast_3 = (temp_alpha * meta.k_ary.sketch_old_3) + ((1 - temp_alpha) * meta.k_ary.forecast_3);
        meta.k_ary.forecast_4 = (temp_alpha * meta.k_ary.sketch_old_4) + ((1 - temp_alpha) * meta.k_ary.forecast_4);

        // Update the forecast registers with the current values.
        register_forecast_0.write((bit<32>)meta.k_ary.hash_0, meta.k_ary.forecast_0);
        register_forecast_1.write((bit<32>)meta.k_ary.hash_1, meta.k_ary.forecast_1);
        register_forecast_2.write((bit<32>)meta.k_ary.hash_2, meta.k_ary.forecast_2);
        register_forecast_3.write((bit<32>)meta.k_ary.hash_3, meta.k_ary.forecast_3);
        register_forecast_4.write((bit<32>)meta.k_ary.hash_4, meta.k_ary.forecast_4);
    }

    action k_ary_forecast_error_sketch() {

        bit<32> temp_sum_old_0;
        bit<32> temp_sum_old_1;
        bit<32> temp_sum_old_2;
        bit<32> temp_sum_old_3;
        bit<32> temp_sum_old_4;

        // Retrieve the current k-ary sum value.
        register_aux.read(meta.k_ary.sum, 2);

        // Retrieve the old forecast error values for the k-ary sum calculation.
        register_error_0.read(temp_sum_old_0, (bit<32>)meta.k_ary.hash_0);
        register_error_1.read(temp_sum_old_1, (bit<32>)meta.k_ary.hash_1);
        register_error_2.read(temp_sum_old_2, (bit<32>)meta.k_ary.hash_2);
        register_error_3.read(temp_sum_old_3, (bit<32>)meta.k_ary.hash_3);
        register_error_4.read(temp_sum_old_4, (bit<32>)meta.k_ary.hash_4);      

        // Update the forecast error registers.
        // Delta between the observed sketch and current forecast. 

        meta.k_ary.error_0 = meta.k_ary.sketch_0 - meta.k_ary.forecast_0;
        meta.k_ary.error_1 = meta.k_ary.sketch_1 - meta.k_ary.forecast_1;
        meta.k_ary.error_2 = meta.k_ary.sketch_2 - meta.k_ary.forecast_2;
        meta.k_ary.error_3 = meta.k_ary.sketch_3 - meta.k_ary.forecast_3;
        meta.k_ary.error_4 = meta.k_ary.sketch_4 - meta.k_ary.forecast_4;

        register_error_0.write((bit<32>)meta.k_ary.hash_0, meta.k_ary.error_0);
        register_error_1.write((bit<32>)meta.k_ary.hash_1, meta.k_ary.error_1);
        register_error_2.write((bit<32>)meta.k_ary.hash_2, meta.k_ary.error_2);
        register_error_3.write((bit<32>)meta.k_ary.hash_3, meta.k_ary.error_3);
        register_error_4.write((bit<32>)meta.k_ary.hash_4, meta.k_ary.error_4);

        // Calculate the current k-ary sum value.
        meta.k_ary.sum = meta.k_ary.sum - temp_sum_old_0 + meta.k_ary.error_0
                                                         - temp_sum_old_1 + meta.k_ary.error_1
                                                         - temp_sum_old_2 + meta.k_ary.error_2
                                                         - temp_sum_old_3 + meta.k_ary.error_3
                                                         - temp_sum_old_4 + meta.k_ary.error_4;

        //Update the k-ary sum value.
        register_aux.write(2, meta.k_ary.sum);                                                              

        // Retrieve the current auxiliary values for F2 (summation block) for each row.
        register_aux.read(meta.k_ary.est_F2_sum_0, (bit<32>)3);
        register_aux.read(meta.k_ary.est_F2_sum_1, (bit<32>)4); 
        register_aux.read(meta.k_ary.est_F2_sum_2, (bit<32>)5); 
        register_aux.read(meta.k_ary.est_F2_sum_3, (bit<32>)6); 
        register_aux.read(meta.k_ary.est_F2_sum_4, (bit<32>)7); 

        // Increase the F2 auxiliary values (summation block) for each row.
        // In each case, if the value of the summation block is 0, the result will be the square product of the sketch value.
        // Otherwise, we subtract the previous iteration of the block, (sketch value -1 ) * (sketch value - 1)
        // and subsequently add the current (sketch value * sketch value) to the block. 

        if (meta.k_ary.est_F2_sum_0 == 0) {
            meta.k_ary.est_F2_sum_0 = meta.k_ary.error_0 * meta.k_ary.error_0;
        } else {
            meta.k_ary.est_F2_sum_0 = meta.k_ary.est_F2_sum_0 - ((meta.k_ary.error_0 - 1) * (meta.k_ary.error_0 - 1));
            meta.k_ary.est_F2_sum_0 = meta.k_ary.est_F2_sum_0 + (meta.k_ary.error_0 * meta.k_ary.error_0);
        }
        if (meta.k_ary.est_F2_sum_1 == 0) {
            meta.k_ary.est_F2_sum_1 = meta.k_ary.error_1 * meta.k_ary.error_1;
        } else {
            meta.k_ary.est_F2_sum_1 = meta.k_ary.est_F2_sum_1 - ((meta.k_ary.error_1 - 1) * (meta.k_ary.error_1 - 1));
            meta.k_ary.est_F2_sum_1 = meta.k_ary.est_F2_sum_1 + (meta.k_ary.error_1 * meta.k_ary.error_1);
        }
        if (meta.k_ary.est_F2_sum_2 == 0) {
            meta.k_ary.est_F2_sum_2 = meta.k_ary.error_2 * meta.k_ary.error_2;
        } else {
            meta.k_ary.est_F2_sum_2 = meta.k_ary.est_F2_sum_2 - ((meta.k_ary.error_2 - 1) * (meta.k_ary.error_2 - 1));
            meta.k_ary.est_F2_sum_2 = meta.k_ary.est_F2_sum_2 + (meta.k_ary.error_2 * meta.k_ary.error_2);
        }
        if (meta.k_ary.est_F2_sum_3 == 0) {
            meta.k_ary.est_F2_sum_3 = meta.k_ary.error_3 * meta.k_ary.error_3;
        } else {
            meta.k_ary.est_F2_sum_3 = meta.k_ary.est_F2_sum_3 - ((meta.k_ary.error_3 - 1) * (meta.k_ary.error_3 - 1));
            meta.k_ary.est_F2_sum_3 = meta.k_ary.est_F2_sum_3 + (meta.k_ary.error_3 * meta.k_ary.error_3);
        }
        if (meta.k_ary.est_F2_sum_4 == 0) {
            meta.k_ary.est_F2_sum_4 = meta.k_ary.error_4 * meta.k_ary.error_4;
        } else {
            meta.k_ary.est_F2_sum_4 = meta.k_ary.est_F2_sum_4 - ((meta.k_ary.error_4 - 1) * (meta.k_ary.error_4 - 1));
            meta.k_ary.est_F2_sum_4 = meta.k_ary.est_F2_sum_4 + (meta.k_ary.error_4 * meta.k_ary.error_4);
        }

        // Update the F2 auxiliary values (summation) for each row.

        register_aux.write((bit<32>)3, meta.k_ary.est_F2_sum_0);
        register_aux.write((bit<32>)4, meta.k_ary.est_F2_sum_1); 
        register_aux.write((bit<32>)5, meta.k_ary.est_F2_sum_2); 
        register_aux.write((bit<32>)6, meta.k_ary.est_F2_sum_3); 
        register_aux.write((bit<32>)7, meta.k_ary.est_F2_sum_4);

    }

    action median(bit<32> aux_0, bit<32> aux_1, bit<32> aux_2, bit<32> aux_3, bit<32> aux_4) {

        if  ((aux_0 <= aux_1 && aux_0 <= aux_2 && aux_0 >= aux_3 && aux_0 >= aux_4) ||
             (aux_0 <= aux_1 && aux_0 <= aux_3 && aux_0 >= aux_2 && aux_0 >= aux_4) ||
             (aux_0 <= aux_1 && aux_0 <= aux_4 && aux_0 >= aux_2 && aux_0 >= aux_3) ||
             (aux_0 <= aux_2 && aux_0 <= aux_3 && aux_0 >= aux_1 && aux_0 >= aux_4) ||
             (aux_0 <= aux_2 && aux_0 <= aux_4 && aux_0 >= aux_1 && aux_0 >= aux_3) ||
             (aux_0 <= aux_3 && aux_0 <= aux_4 && aux_0 >= aux_1 && aux_0 >= aux_2)) {
                meta.k_ary.median = aux_0;
        } 
        else if ((aux_1 <= aux_0 && aux_1 <= aux_2 && aux_1 >= aux_3 && aux_1 >= aux_4) ||
                 (aux_1 <= aux_0 && aux_1 <= aux_3 && aux_1 >= aux_2 && aux_1 >= aux_4) ||
                 (aux_1 <= aux_0 && aux_1 <= aux_4 && aux_1 >= aux_2 && aux_1 >= aux_3) ||
                 (aux_1 <= aux_2 && aux_1 <= aux_3 && aux_1 >= aux_0 && aux_1 >= aux_4) ||
                 (aux_1 <= aux_2 && aux_1 <= aux_4 && aux_1 >= aux_0 && aux_1 >= aux_3) ||
                 (aux_1 <= aux_3 && aux_1 <= aux_4 && aux_1 >= aux_0 && aux_1 >= aux_2)) {
                    meta.k_ary.median = aux_1;
        }
        else if ((aux_2 <= aux_1 && aux_2 <= aux_0 && aux_2 >= aux_3 && aux_2 >= aux_4) ||
                 (aux_2 <= aux_1 && aux_2 <= aux_3 && aux_2 >= aux_0 && aux_2 >= aux_4) ||
                 (aux_2 <= aux_1 && aux_2 <= aux_4 && aux_2 >= aux_0 && aux_2 >= aux_3) ||
                 (aux_2 <= aux_0 && aux_2 <= aux_3 && aux_2 >= aux_1 && aux_2 >= aux_4) ||
                 (aux_2 <= aux_0 && aux_2 <= aux_4 && aux_2 >= aux_1 && aux_2 >= aux_3) ||
                 (aux_2 <= aux_3 && aux_2 <= aux_4 && aux_2 >= aux_1 && aux_2 >= aux_0)) {
                    meta.k_ary.median = aux_2;
        }
        else if ((aux_3 <= aux_1 && aux_3 <= aux_2 && aux_3 >= aux_0 && aux_3 >= aux_4) ||
                 (aux_3 <= aux_1 && aux_3 <= aux_0 && aux_3 >= aux_2 && aux_3 >= aux_4) ||
                 (aux_3 <= aux_1 && aux_3 <= aux_4 && aux_3 >= aux_2 && aux_3 >= aux_0) ||
                 (aux_3 <= aux_2 && aux_3 <= aux_0 && aux_3 >= aux_1 && aux_3 >= aux_4) ||
                 (aux_3 <= aux_2 && aux_3 <= aux_4 && aux_3 >= aux_1 && aux_3 >= aux_0) ||
                 (aux_3 <= aux_0 && aux_3 <= aux_4 && aux_3 >= aux_1 && aux_3 >= aux_2)) {
                    meta.k_ary.median = aux_3;
        }
        else {
            meta.k_ary.median = aux_4;
        }
    }    

    action k_ary_estimate_row() {

        // Calculate the estimate for each row.
		// TODO here counting started from 1 to 5 in the rh exp, I had to change it 
        meta.k_ary.est_row_0 = (meta.k_ary.error_0 - (meta.k_ary.sum / REG_SKETCH_SIZE)) / (1 - (1 / REG_SKETCH_SIZE));
        meta.k_ary.est_row_1 = (meta.k_ary.error_1 - (meta.k_ary.sum / REG_SKETCH_SIZE)) / (1 - (1 / REG_SKETCH_SIZE));
        meta.k_ary.est_row_2 = (meta.k_ary.error_2 - (meta.k_ary.sum / REG_SKETCH_SIZE)) / (1 - (1 / REG_SKETCH_SIZE));
        meta.k_ary.est_row_3 = (meta.k_ary.error_3 - (meta.k_ary.sum / REG_SKETCH_SIZE)) / (1 - (1 / REG_SKETCH_SIZE));
        meta.k_ary.est_row_4 = (meta.k_ary.error_4 - (meta.k_ary.sum / REG_SKETCH_SIZE)) / (1 - (1 / REG_SKETCH_SIZE));
    }

    action k_ary_estimate_write() {
		// TODO the line below had names not valid for the current metadata, what was that? Sth left from a prev impl?
        //register_estimate.write((bit<32>)meta.k_ary.hash_0, meta.k_ary.median);
        register_estimate.write((bit<32>)meta.k_ary.hash_0, meta.k_ary.median);
    }

    action k_ary_estimate_F2_row() {

        // Retrieve the F2 auxiliary values for each row.

        register_aux.read(meta.k_ary.est_F2_sum_0, (bit<32>)3);
        register_aux.read(meta.k_ary.est_F2_sum_1, (bit<32>)4); 
        register_aux.read(meta.k_ary.est_F2_sum_2, (bit<32>)5); 
        register_aux.read(meta.k_ary.est_F2_sum_3, (bit<32>)6); 
        register_aux.read(meta.k_ary.est_F2_sum_4, (bit<32>)7);        

        // Retrieve the current k-ary sum value.
        register_aux.read(meta.k_ary.sum, 2);

        // Calculate the estimate F2 for each row.

        meta.k_ary.est_F2_sum_0 = (REG_SKETCH_SIZE / (REG_SKETCH_SIZE - 1)) * (meta.k_ary.est_F2_sum_0) - (1 / (REG_SKETCH_SIZE - 1)) * (meta.k_ary.sum * meta.k_ary.sum);
        meta.k_ary.est_F2_sum_1 = (REG_SKETCH_SIZE / (REG_SKETCH_SIZE - 1)) * (meta.k_ary.est_F2_sum_1) - (1 / (REG_SKETCH_SIZE - 1)) * (meta.k_ary.sum * meta.k_ary.sum);
        meta.k_ary.est_F2_sum_2 = (REG_SKETCH_SIZE / (REG_SKETCH_SIZE - 1)) * (meta.k_ary.est_F2_sum_2) - (1 / (REG_SKETCH_SIZE - 1)) * (meta.k_ary.sum * meta.k_ary.sum);
        meta.k_ary.est_F2_sum_3 = (REG_SKETCH_SIZE / (REG_SKETCH_SIZE - 1)) * (meta.k_ary.est_F2_sum_3) - (1 / (REG_SKETCH_SIZE - 1)) * (meta.k_ary.sum * meta.k_ary.sum);
        meta.k_ary.est_F2_sum_4 = (REG_SKETCH_SIZE / (REG_SKETCH_SIZE - 1)) * (meta.k_ary.est_F2_sum_4) - (1 / (REG_SKETCH_SIZE - 1)) * (meta.k_ary.sum * meta.k_ary.sum);
    }

    action k_ary_estimate_F2_write() {
        // When this action is executed, the current median meta value is estimate F2.
        register_aux.write((bit<32>)8, meta.k_ary.median);
    }             

	apply {

	    hash_0();
	    hash_1();
	    hash_2();
	    hash_3();
	    hash_4();

	    k_ary_sketch_incr();

	    // Exponencially Weighted Moving Average (EWMA).
	    // If t_interval = 2, the current forecast value corresponds to the observed sketch of previous interval.
	    // Else, when i_interval > 2, the forecast value is the weighted average of the previous forecast 
	    // and the newly observed sample at time t - 1.

	    register_aux.read(meta.k_ary.t_interval, (bit<32>)0);

	    if (meta.k_ary.t_interval == 2) {
	        k_ary_forecast_interval_t_equals_2();
	    } else {
	        k_ary_forecast_interval();
	    }

	    // The k-ary forecast error sketch is the delta between the observed sketch and the forecast sketch.
	    k_ary_forecast_error_sketch();

	    // K-ary sketch estimate.

	    k_ary_estimate_row();

	    median(meta.k_ary.est_row_0, 
	           meta.k_ary.est_row_1,
	           meta.k_ary.est_row_2,
	           meta.k_ary.est_row_3,
	           meta.k_ary.est_row_4);

	    k_ary_estimate_write();

        // Check if the current packet is part of a pingall.
        // Only run k-ary's estimate F2 if true.

        hash_ping();

        if ((bit<32>)meta.meta.hash_ping == hash_ping) {

            // Estimate F2
            
            k_ary_estimate_F2_row();
            
            median(meta.k_ary.est_F2_sum_0, 
                   meta.k_ary.est_F2_sum_1,
                   meta.k_ary.est_F2_sum_2,
                   meta.k_ary.est_F2_sum_3,
                   meta.k_ary.est_F2_sum_4);
            
            k_ary_estimate_F2_write();
        }	    
	}
}