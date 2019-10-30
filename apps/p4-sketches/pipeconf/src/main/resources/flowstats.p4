
#include <core.p4>
#include <v1model.p4>

#include "includes/constants.p4"
#include "includes/headers.p4"
#include "includes/parser.p4"
#include "includes/deparser.p4"

//------------------------------------------------------------------------------
// INGRESS PIPELINE
//------------------------------------------------------------------------------

control c_ingress(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

    register<bit<32>>(REG_SKETCH_SIZE)  cm_0_register;
    register<bit<32>>(REG_SKETCH_SIZE)  cm_1_register;  
    register<bit<32>>(REG_SKETCH_SIZE)  cm_2_register;  
    register<bit<32>>(REG_SKETCH_SIZE)  cm_final_register;
    
    register<bit<32>>(REG_SKETCH_SIZE)  bm_0_register;
    // Bitmap register for the source address.
    register<bit<32>>(REG_SKETCH_SIZE)  bm_1_register;
    // Bitmap register for the destination address.
    register<bit<32>>(REG_SKETCH_SIZE)  bm_2_register;


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

    bit<32> cm_0_hash;
    bit<32> cm_1_hash;
    bit<32> cm_2_hash;

    bit<32> bm_0_hash;
    // Bitmap hash for the source address.
    bit<32> bm_1_hash;
    // Bitmap hash for the destination address.
    bit<32> bm_2_hash;

    bit<32> k_ary_0_hash;
    bit<32> k_ary_1_hash;
    bit<32> k_ary_2_hash;
    bit<32> k_ary_3_hash;
    bit<32> k_ary_4_hash;

    // We use these counters to count packets/bytes received/sent on each port.
    // For each counter we instantiate a number of cells equal to MAX_PORTS.
    counter(MAX_PORTS, CounterType.packets_and_bytes) tx_port_counter;
    counter(MAX_PORTS, CounterType.packets_and_bytes) rx_port_counter;

    action send_to_cpu() {
        // Packets sent to the controller needs to be prepended with the packet-in header.
        // By setting it valid we make sure it will be deparsed on the wire (see c_deparser).
        standard_metadata.egress_spec = CPU_PORT;
        hdr.packet_in.setValid();
        hdr.packet_in.ingress_port = standard_metadata.ingress_port;
    }

    action set_out_port(port_t port) {
        // Specifies the output port for this packet by setting the corresponding metadata.
        standard_metadata.egress_spec = port;
    }

    action _drop() {}

    // Count-min sketch actions

    action cm_0_hash() {
        hash(cm_0_hash, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr}, 
            (bit<32>)REG_SKETCH_SIZE);
        meta.cm_meta.cm_0_hash = cm_0_hash;
    }

    action cm_1_hash() {
        hash(cm_1_hash, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr}, 
            (bit<32>)REG_SKETCH_SIZE);
        meta.cm_meta.cm_1_hash = cm_1_hash;
    }

    action cm_2_hash() {
        hash(cm_2_hash, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr},
            (bit<32>)REG_SKETCH_SIZE);
        meta.cm_meta.cm_2_hash = cm_2_hash;
    }      

    action cm_incr() {

        cm_0_register.read(meta.cm_meta.cm_0_sketch, (bit<32>)meta.cm_meta.cm_0_hash);
        cm_1_register.read(meta.cm_meta.cm_1_sketch, (bit<32>)meta.cm_meta.cm_1_hash);
        cm_2_register.read(meta.cm_meta.cm_2_sketch, (bit<32>)meta.cm_meta.cm_2_hash);

        // Incrementation is made using the metadata, instead of directly on the registers.
        // This allows us to perform the final value comparison on the apply{} block.
        meta.cm_meta.cm_0_sketch = meta.cm_meta.cm_0_sketch + 1;
        meta.cm_meta.cm_1_sketch = meta.cm_meta.cm_1_sketch + 1;
        meta.cm_meta.cm_2_sketch = meta.cm_meta.cm_2_sketch + 1;

        cm_0_register.write((bit<32>)meta.cm_meta.cm_0_hash, meta.cm_meta.cm_0_sketch);
        cm_1_register.write((bit<32>)meta.cm_meta.cm_1_hash, meta.cm_meta.cm_1_sketch);
        cm_2_register.write((bit<32>)meta.cm_meta.cm_2_hash, meta.cm_meta.cm_2_sketch);
    }

    action cm_register_write() {
        cm_final_register.write((bit<32>)meta.cm_meta.cm_2_hash, meta.cm_meta.cm_final_sketch);
    }

    // Bitmap sketch actions

    action bm_0_hash() {
        hash(bm_0_hash,
            HashAlgorithm.crc32_custom,
            (bit<32>)0,
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.meta.l4_src_port, (bit<32>)meta.meta.l4_dst_port},
            (bit<32>)REG_SKETCH_SIZE);
        meta.bm_meta.bm_0_hash = bm_0_hash;
    }

    action bm_1_hash() {
        hash(bm_1_hash, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.meta.l4_src_port}, 
            (bit<32>)REG_SKETCH_SIZE);
        meta.bm_meta.bm_1_hash = bm_1_hash;
    }

    action bm_2_hash() {
        hash(bm_2_hash, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.meta.l4_dst_port}, 
            (bit<32>)REG_SKETCH_SIZE);
        meta.bm_meta.bm_2_hash = bm_2_hash;
    }          

    action bm_check_pair() {

        // Check the bitmap value for the (ip src, ip dst) pair
        bm_0_register.read(meta.bm_meta.bm_0_sketch, (bit<32>)meta.bm_meta.bm_0_hash);
    }

    action bm_new_pair() {
        
        bm_1_register.read(meta.bm_meta.bm_1_sketch, (bit<32>)meta.bm_meta.bm_1_hash);
        bm_2_register.read(meta.bm_meta.bm_2_sketch, (bit<32>)meta.bm_meta.bm_2_hash);

        bm_0_register.write((bit<32>)meta.bm_meta.bm_0_hash, 1);
        bm_1_register.write((bit<32>)meta.bm_meta.bm_1_hash, meta.bm_meta.bm_1_sketch + 1);
        bm_2_register.write((bit<32>)meta.bm_meta.bm_2_hash, meta.bm_meta.bm_2_sketch + 1);
    }

    // K-ary sketch actions

    action k_ary_0_hash() {
        hash(k_ary_0_hash, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr}, 
            (bit<32>)REG_SKETCH_SIZE);
        meta.k_ary_meta.k_ary_0_hash = k_ary_0_hash;
    }

    action k_ary_1_hash() {
        hash(k_ary_1_hash, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr}, 
            (bit<32>)REG_SKETCH_SIZE);
        meta.k_ary_meta.k_ary_1_hash = k_ary_1_hash;
    }

    action k_ary_2_hash() {
        hash(k_ary_2_hash, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr}, 
            (bit<32>)REG_SKETCH_SIZE);
        meta.k_ary_meta.k_ary_2_hash = k_ary_2_hash;
    }

    action k_ary_3_hash() {
        hash(k_ary_3_hash, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr}, 
            (bit<32>)REG_SKETCH_SIZE);
        meta.k_ary_meta.k_ary_3_hash = k_ary_3_hash;
    }

    action k_ary_4_hash() {
        hash(k_ary_4_hash, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr}, 
            (bit<32>)REG_SKETCH_SIZE);
        meta.k_ary_meta.k_ary_4_hash = k_ary_4_hash;
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

        meta.k_ary_meta.k_ary_0_sketch++;
        meta.k_ary_meta.k_ary_1_sketch++;
        meta.k_ary_meta.k_ary_2_sketch++;
        meta.k_ary_meta.k_ary_3_sketch++;
        meta.k_ary_meta.k_ary_4_sketch++;

        k_ary_0_sketch_register.write((bit<32)meta.k_ary_meta.k_ary_0_hash, meta.k_ary_meta.k_ary_0_sketch);
        k_ary_1_sketch_register.write((bit<32)meta.k_ary_meta.k_ary_1_hash, meta.k_ary_meta.k_ary_1_sketch);
        k_ary_2_sketch_register.write((bit<32)meta.k_ary_meta.k_ary_2_hash, meta.k_ary_meta.k_ary_2_sketch);
        k_ary_3_sketch_register.write((bit<32)meta.k_ary_meta.k_ary_3_hash, meta.k_ary_meta.k_ary_3_sketch);
        k_ary_4_sketch_register.write((bit<32)meta.k_ary_meta.k_ary_4_hash, meta.k_ary_meta.k_ary_4_sketch);
    }

    action k_ary_forecast_interval_t_equals_2() {      

        // Update the forecast registers with the current values.
        k_ary_0_forecast_register.write((bit<32)meta.k_ary_meta.k_ary_0_hash, meta.k_ary_meta.k_ary_0_sketch_old);
        k_ary_1_forecast_register.write((bit<32)meta.k_ary_meta.k_ary_1_hash, meta.k_ary_meta.k_ary_1_sketch_old);
        k_ary_2_forecast_register.write((bit<32)meta.k_ary_meta.k_ary_2_hash, meta.k_ary_meta.k_ary_2_sketch_old);
        k_ary_3_forecast_register.write((bit<32)meta.k_ary_meta.k_ary_3_hash, meta.k_ary_meta.k_ary_3_sketch_old);
        k_ary_4_forecast_register.write((bit<32)meta.k_ary_meta.k_ary_4_hash, meta.k_ary_meta.k_ary_4_sketch_old);
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
        meta.k_ary_meta.est_row_0 = (meta.k_ary_meta.k_ary_1_error_sketch - (meta.k_ary_meta.k_ary_sum / REG_SKETCH_SIZE)) / (1 - (1 / REG_SKETCH_SIZE));
        meta.k_ary_meta.est_row_1 = (meta.k_ary_meta.k_ary_2_error_sketch - (meta.k_ary_meta.k_ary_sum / REG_SKETCH_SIZE)) / (1 - (1 / REG_SKETCH_SIZE));
        meta.k_ary_meta.est_row_2 = (meta.k_ary_meta.k_ary_3_error_sketch - (meta.k_ary_meta.k_ary_sum / REG_SKETCH_SIZE)) / (1 - (1 / REG_SKETCH_SIZE));
        meta.k_ary_meta.est_row_3 = (meta.k_ary_meta.k_ary_4_error_sketch - (meta.k_ary_meta.k_ary_sum / REG_SKETCH_SIZE)) / (1 - (1 / REG_SKETCH_SIZE));
        meta.k_ary_meta.est_row_4 = (meta.k_ary_meta.k_ary_5_error_sketch - (meta.k_ary_meta.k_ary_sum / REG_SKETCH_SIZE)) / (1 - (1 / REG_SKETCH_SIZE));
    }

    action k_ary_estimate_write() {
        k_ary_register_estimate.write((bit<32>)meta.meta_k_ary.hash_0, meta.meta_k_ary.median);
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

    // Ping hash.

    action action_get_ping_hash() {
        hash(ping_hash, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr}, 
            (bit<32>)REG_SKETCH_SIZE);
        meta.meta.ping_hash = ping_hash;
    }     

    // Table counter used to count packets and bytes matched by each entry of t_l2_fwd table.
    direct_counter(CounterType.packets_and_bytes) l2_fwd_counter;

    table t_l2_fwd {
        key = {
            standard_metadata.ingress_port  : ternary;
            hdr.ethernet.dst_addr           : ternary;
            hdr.ethernet.src_addr           : ternary;
            hdr.ethernet.ether_type         : ternary;
            hdr.ipv4.protocol               : ternary;
            hdr.ipv4.src_addr               : ternary;
            hdr.ipv4.dst_addr               : ternary;
            hdr.tcp.src_port                : ternary;
            hdr.tcp.dst_port                : ternary;
            hdr.udp.src_port                : ternary;
            hdr.udp.dst_port                : ternary;
        }
        actions = {
            set_out_port;
            send_to_cpu;
            _drop;
            NoAction;
        }
        default_action = NoAction();
        size = 524288;
        counters = l2_fwd_counter;
    }          

    // Defines the processing applied by this control block. 
    // You can see this as the main function applied to every packet received by the switch.
    apply {
        if (standard_metadata.ingress_port == CPU_PORT) {
            // Packet received from CPU_PORT, this is a packet-out sent by the controller. 
            // Skip table processing, set the egress port as requested by the controller (packet_out header) and remove the packet_out header.           
            standard_metadata.egress_spec = hdr.packet_out.egress_port;
            hdr.packet_out.setInvalid();
        } else {
            // Packet received from data plane port.
            // Applies table t_l2_fwd to the packet.
            if (t_l2_fwd.apply().hit) {

                // Check if the current packet is part of a pingall.
                // Only run k-ary's estimate F2 if true.

                get_ping_hash();

                if ((bit<32>)meta.meta.ping_hash == (bit<32>)93017) {

                    // Estimate F2
                    
                    k_ary_estimate_F2_row();
                    
                    k_ary_median(meta.k_ary_meta.k_ary_0_est_F2_sum, 
                                 meta.k_ary_meta.k_ary_1_est_F2_sum,
                                 meta.k_ary_meta.k_ary_2_est_F2_sum,
                                 meta.k_ary_meta.k_ary_3_est_F2_sum,
                                 meta.k_ary_meta.k_ary_4_est_F2_sum);
                    
                    k_ary_estimate_F2_write();
                
                } else {

                    // Count-min sketch.

                    cm_0_hash();
                    cm_1_hash();
                    cm_2_hash();
                    
                    // Increment the value on all registers.
                    cm_incr();

                    // Compare the current value on all registers and identify the smallest.
                    meta.cm_meta.cm_final_sketch = meta.cm_meta.cm_0_sketch;

                    if (meta.cm_meta.cm_final_sketch > meta.cm_meta.cm_1_sketch) {
                        meta.cm_meta.cm_final_sketch = meta.cm_meta.cm_1_sketch;
                    }
                    
                    if (meta.cm_meta.cm_final_sketch > meta.cm_meta.cm_2_sketch) {
                        meta.cm_meta.cm_final_sketch = meta.cm_meta.cm_2_sketch;
                    }

                    // Write the smallest value to the final count-min register.
                    cm_register_write();  
                    
                    // Bitmap sketch.

                    bm_0_hash();
                    bm_1_hash();
                    bm_2_hash();                
         
                    // Check the bitmap value for the (ip src, ip dst) pair.
                    bm_check_pair();

                    // If the value is 0, it means we have a new pair.
                    // write the bitmap value on register 0 and increase the counter for the ip src on register1.
                    if (meta.bm_meta.bm_0_sketch == 0) {
                        bm_new_pair();
                    }

                    // K-ary sketch.

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
                }                

                // Packet hit an entry in t_l2_fwd table. A forwarding action has already been taken.
                // No need to apply other tables, exit this control block.                
                return;
            }
        }

        if (standard_metadata.egress_spec < MAX_PORTS) {
            tx_port_counter.count((bit<32>) standard_metadata.egress_spec);
        }
        if (standard_metadata.ingress_port < MAX_PORTS) {
            rx_port_counter.count((bit<32>) standard_metadata.ingress_port);
        }        
     }
}

//------------------------------------------------------------------------------
// EGRESS PIPELINE
//------------------------------------------------------------------------------

control c_egress(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {
    apply {}
}

//------------------------------------------------------------------------------
// CHECKSUM HANDLING
//------------------------------------------------------------------------------

control c_verify_checksum(inout headers_t hdr, inout metadata_t meta) {
    apply {}
}

control c_compute_checksum(inout headers_t hdr, inout metadata_t meta) {
    apply {}
}

//------------------------------------------------------------------------------
// SWITCH INSTANTIATION
//------------------------------------------------------------------------------

V1Switch(c_parser(), c_verify_checksum(), c_ingress(), c_egress(), c_compute_checksum(), c_deparser()) main;
