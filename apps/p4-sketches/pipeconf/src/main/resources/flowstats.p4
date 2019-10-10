
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

    register<bit<32>>(REG_SKETCH_SIZE)  cm_register_0;
    register<bit<32>>(REG_SKETCH_SIZE)  cm_register_1;  
    register<bit<32>>(REG_SKETCH_SIZE)  cm_register_2;  
    register<bit<32>>(REG_SKETCH_SIZE)  cm_register_final;
    
    register<bit<32>>(REG_SKETCH_SIZE)  bm_register_0;
    // Bitmap register for the source address.
    register<bit<32>>(REG_SKETCH_SIZE)  bm_register_1;
    // Bitmap register for the destination address.
    register<bit<32>>(REG_SKETCH_SIZE)  bm_register_2;

    register<bit<32>>(REG_SKETCH_SIZE)  k_ary_register_0;
    register<bit<32>>(REG_SKETCH_SIZE)  k_ary_register_1;
    register<bit<32>>(REG_SKETCH_SIZE)  k_ary_register_2;
    register<bit<32>>(REG_SKETCH_SIZE)  k_ary_register_3;
    register<bit<32>>(REG_SKETCH_SIZE)  k_ary_register_4;
    register<bit<32>>(REG_SKETCH_SIZE)  k_ary_register_estimate;
    register<bit<32>>(10)               k_ary_register_final;

    bit<32> cm_hash_0;
    bit<32> cm_hash_1;
    bit<32> cm_hash_2;

    bit<32> bm_hash_0;
    // Bitmap hash for the source address.
    bit<32> bm_hash_1;
    // Bitmap hash for the destination address.
    bit<32> bm_hash_2;

    bit<32> k_ary_hash_0;
    bit<32> k_ary_hash_1;
    bit<32> k_ary_hash_2;
    bit<32> k_ary_hash_3;
    bit<32> k_ary_hash_4;

    bit<32> ping_hash;

    // We use these counters to count packets/bytes received/sent on each port.
    // For each counter we instantiate a number of cells equal to MAX_PORTS.
    counter(MAX_PORTS, CounterType.packets_and_bytes) tx_port_counter;
    counter(MAX_PORTS, CounterType.packets_and_bytes) rx_port_counter;

    action send_to_cpu() {
        // Packets sent to the controller needs to be prepended with the
        // packet-in header. By setting it valid we make sure it will be
        // deparsed on the wire (see c_deparser).
        standard_metadata.egress_spec = CPU_PORT;
        hdr.packet_in.setValid();
        hdr.packet_in.ingress_port = standard_metadata.ingress_port;
    }

    action set_out_port(port_t port) {
        // Specifies the output port for this packet by setting the
        // corresponding metadata.
        standard_metadata.egress_spec = port;
    }

    action _drop() {}

    // Count-min sketch actions

    action action_get_cm_hash_0() {
        hash(cm_hash_0, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr}, 
            (bit<32>)REG_SKETCH_SIZE);
        meta.meta_cm.hash_0 = cm_hash_0;
    }

    action action_get_cm_hash_1() {
        hash(cm_hash_1, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr}, 
            (bit<32>)REG_SKETCH_SIZE);
        meta.meta_cm.hash_1 = cm_hash_1;
    }

    action action_get_cm_hash_2() {
        hash(cm_hash_2, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr},
            (bit<32>)REG_SKETCH_SIZE);
        meta.meta_cm.hash_2 = cm_hash_2;
    }      

    action action_cm_sketch_incr() {

        cm_register_0.read(meta.meta_cm.sketch_0, (bit<32>)meta.meta_cm.hash_0);
        cm_register_1.read(meta.meta_cm.sketch_1, (bit<32>)meta.meta_cm.hash_1);
        cm_register_2.read(meta.meta_cm.sketch_2, (bit<32>)meta.meta_cm.hash_2);

        meta.meta_cm.sketch_0 = meta.meta_cm.sketch_0 + 1;
        meta.meta_cm.sketch_1 = meta.meta_cm.sketch_1 + 1;
        meta.meta_cm.sketch_2 = meta.meta_cm.sketch_2 + 1;        

        cm_register_0.write((bit<32>)meta.meta_cm.hash_0, meta.meta_cm.sketch_0);
        cm_register_1.write((bit<32>)meta.meta_cm.hash_1, meta.meta_cm.sketch_1);
        cm_register_2.write((bit<32>)meta.meta_cm.hash_2, meta.meta_cm.sketch_2);
    }

    action action_cm_register_write() {
        cm_register_final.write((bit<32>)meta.meta_cm.hash_2, meta.meta_cm.sketch_final);
    }

    // Bitmap sketch actions

    action action_bm_hash_0() {
        hash(bm_hash_0,
            HashAlgorithm.crc32_custom,
            (bit<32>)0,
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.meta.l4_src_port, (bit<32>)meta.meta.l4_dst_port},
            (bit<32>)REG_SKETCH_SIZE);
        meta.meta_bm.hash_0 = bm_hash_0;
    }

    action action_bm_hash_1() {
        hash(bm_hash_1, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.meta.l4_src_port}, 
            (bit<32>)REG_SKETCH_SIZE);
        meta.meta_bm.hash_1 = bm_hash_1;
    }

    action action_bm_hash_2() {
        hash(bm_hash_2, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.meta.l4_dst_port}, 
            (bit<32>)REG_SKETCH_SIZE);
        meta.meta_bm.hash_2 = bm_hash_2;
    }          

    action action_bm_check_pair() {

        // Check the bitmap value for the (ip src, ip dst) pair
        bm_register_0.read(meta.meta_bm.sketch_0, (bit<32>)meta.meta_bm.hash_0);
    }

    action action_bm_new_pair() {
        
        bm_register_1.read(meta.meta_bm.sketch_1, (bit<32>)meta.meta_bm.hash_1);
        bm_register_2.read(meta.meta_bm.sketch_2, (bit<32>)meta.meta_bm.hash_2);

        bm_register_0.write((bit<32>)meta.meta_bm.hash_0, 1);
        bm_register_1.write((bit<32>)meta.meta_bm.hash_1, meta.meta_bm.sketch_1 + 1);
        bm_register_2.write((bit<32>)meta.meta_bm.hash_2, meta.meta_bm.sketch_2 + 1);
    }  

    // K-ary sketch actions

    action action_get_k_ary_hash_0() {
        hash(k_ary_hash_0, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr}, 
            (bit<32>)REG_SKETCH_SIZE);
        meta.meta_k_ary.hash_0 = k_ary_hash_0;
    }

    action action_get_k_ary_hash_1() {
        hash(k_ary_hash_1, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr}, 
            (bit<32>)REG_SKETCH_SIZE);
        meta.meta_k_ary.hash_1 = k_ary_hash_1;
    }

    action action_get_k_ary_hash_2() {
        hash(k_ary_hash_2, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr}, 
            (bit<32>)REG_SKETCH_SIZE);
        meta.meta_k_ary.hash_2 = k_ary_hash_2;
    }

    action action_get_k_ary_hash_3() {
        hash(k_ary_hash_3, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr}, 
            (bit<32>)REG_SKETCH_SIZE);
        meta.meta_k_ary.hash_3 = k_ary_hash_3;
    }

    action action_get_k_ary_hash_4() {
        hash(k_ary_hash_4, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr}, 
            (bit<32>)REG_SKETCH_SIZE);
        meta.meta_k_ary.hash_4 = k_ary_hash_4;
    }

    action action_k_ary_sketch_incr() {

        // Retrieve the current sketch values.

        k_ary_register_0.read(meta.meta_k_ary.sketch_0, (bit<32>)meta.meta_k_ary.hash_0);
        k_ary_register_1.read(meta.meta_k_ary.sketch_1, (bit<32>)meta.meta_k_ary.hash_1);
        k_ary_register_2.read(meta.meta_k_ary.sketch_2, (bit<32>)meta.meta_k_ary.hash_2);
        k_ary_register_3.read(meta.meta_k_ary.sketch_3, (bit<32>)meta.meta_k_ary.hash_3);
        k_ary_register_4.read(meta.meta_k_ary.sketch_4, (bit<32>)meta.meta_k_ary.hash_4);

        // Retrieve the current sum of all values.

        k_ary_register_final.read(meta.meta_k_ary.sum, (bit<32>)6);

        // Retrieve the current auxiliary values for F2 (summation block) for each row.

        k_ary_register_final.read(meta.meta_k_ary.est_F2_sum_0, (bit<32>)0);
        k_ary_register_final.read(meta.meta_k_ary.est_F2_sum_1, (bit<32>)1); 
        k_ary_register_final.read(meta.meta_k_ary.est_F2_sum_2, (bit<32>)2); 
        k_ary_register_final.read(meta.meta_k_ary.est_F2_sum_3, (bit<32>)3); 
        k_ary_register_final.read(meta.meta_k_ary.est_F2_sum_4, (bit<32>)4);        
        
        // Increase the sketch values.

        meta.meta_k_ary.sketch_0 = meta.meta_k_ary.sketch_0 + 1;
        meta.meta_k_ary.sketch_1 = meta.meta_k_ary.sketch_1 + 1;
        meta.meta_k_ary.sketch_2 = meta.meta_k_ary.sketch_2 + 1;
        meta.meta_k_ary.sketch_3 = meta.meta_k_ary.sketch_3 + 1;
        meta.meta_k_ary.sketch_4 = meta.meta_k_ary.sketch_4 + 1;

        // Increase the F2 auxiliary values (summation block) for each row.
        // In each case, if the value of the summation block is 0, the result will be the square product of the sketch value.
        // Otherwise, we subtract the previous iteration of the block, (sketch value -1 ) * (sketch value - 1)
        // and subsequently add the current (sketch value * sketch value) to the block. 

        if (meta.meta_k_ary.est_F2_sum_0 == 0) {
            meta.meta_k_ary.est_F2_sum_0 = meta.meta_k_ary.sketch_0 * meta.meta_k_ary.sketch_0;
        } else {
            meta.meta_k_ary.est_F2_sum_0 = meta.meta_k_ary.est_F2_sum_0 - ((meta.meta_k_ary.sketch_0 - 1) * (meta.meta_k_ary.sketch_0 - 1));
            meta.meta_k_ary.est_F2_sum_0 = meta.meta_k_ary.est_F2_sum_0 + (meta.meta_k_ary.sketch_0 * meta.meta_k_ary.sketch_0);
        }
        if (meta.meta_k_ary.est_F2_sum_1 == 0) {
            meta.meta_k_ary.est_F2_sum_1 = meta.meta_k_ary.sketch_1 * meta.meta_k_ary.sketch_1;
        } else {
            meta.meta_k_ary.est_F2_sum_1 = meta.meta_k_ary.est_F2_sum_1 - ((meta.meta_k_ary.sketch_1 - 1) * (meta.meta_k_ary.sketch_1 - 1));
            meta.meta_k_ary.est_F2_sum_1 = meta.meta_k_ary.est_F2_sum_1 + (meta.meta_k_ary.sketch_1 * meta.meta_k_ary.sketch_1);
        }
        if (meta.meta_k_ary.est_F2_sum_2 == 0) {
            meta.meta_k_ary.est_F2_sum_2 = meta.meta_k_ary.sketch_2 * meta.meta_k_ary.sketch_2;
        } else {
            meta.meta_k_ary.est_F2_sum_2 = meta.meta_k_ary.est_F2_sum_2 - ((meta.meta_k_ary.sketch_2 - 1) * (meta.meta_k_ary.sketch_2 - 1));
            meta.meta_k_ary.est_F2_sum_2 = meta.meta_k_ary.est_F2_sum_2 + (meta.meta_k_ary.sketch_2 * meta.meta_k_ary.sketch_2);
        }
        if (meta.meta_k_ary.est_F2_sum_3 == 0) {
            meta.meta_k_ary.est_F2_sum_3 = meta.meta_k_ary.sketch_3 * meta.meta_k_ary.sketch_3;
        } else {
            meta.meta_k_ary.est_F2_sum_3 = meta.meta_k_ary.est_F2_sum_3 - ((meta.meta_k_ary.sketch_3 - 1) * (meta.meta_k_ary.sketch_3 - 1));
            meta.meta_k_ary.est_F2_sum_3 = meta.meta_k_ary.est_F2_sum_3 + (meta.meta_k_ary.sketch_3 * meta.meta_k_ary.sketch_3);
        }
        if (meta.meta_k_ary.est_F2_sum_4 == 0) {
            meta.meta_k_ary.est_F2_sum_4 = meta.meta_k_ary.sketch_4 * meta.meta_k_ary.sketch_4;
        } else {
            meta.meta_k_ary.est_F2_sum_4 = meta.meta_k_ary.est_F2_sum_4 - ((meta.meta_k_ary.sketch_4 - 1) * (meta.meta_k_ary.sketch_4 - 1));
            meta.meta_k_ary.est_F2_sum_4 = meta.meta_k_ary.est_F2_sum_4 + (meta.meta_k_ary.sketch_4 * meta.meta_k_ary.sketch_4);
        }

        // Update the current sketch values.

        k_ary_register_0.write((bit<32>)meta.meta_k_ary.hash_0, meta.meta_k_ary.sketch_0);
        k_ary_register_1.write((bit<32>)meta.meta_k_ary.hash_1, meta.meta_k_ary.sketch_1);
        k_ary_register_2.write((bit<32>)meta.meta_k_ary.hash_2, meta.meta_k_ary.sketch_2);
        k_ary_register_3.write((bit<32>)meta.meta_k_ary.hash_3, meta.meta_k_ary.sketch_3);
        k_ary_register_4.write((bit<32>)meta.meta_k_ary.hash_4, meta.meta_k_ary.sketch_4);

        // Update the current sum of all values.

        k_ary_register_final.write((bit<32>)6, meta.meta_k_ary.sum + 5);

        // Update the F2 auxiliary values (summation) for each row.

        k_ary_register_final.write((bit<32>)0, meta.meta_k_ary.est_F2_sum_0);
        k_ary_register_final.write((bit<32>)1, meta.meta_k_ary.est_F2_sum_1); 
        k_ary_register_final.write((bit<32>)2, meta.meta_k_ary.est_F2_sum_2); 
        k_ary_register_final.write((bit<32>)3, meta.meta_k_ary.est_F2_sum_3); 
        k_ary_register_final.write((bit<32>)4, meta.meta_k_ary.est_F2_sum_4);
    }

    action action_k_ary_median(bit<32> aux_0, bit<32> aux_1, bit<32> aux_2, bit<32> aux_3, bit<32> aux_4) {

        if  ((aux_0 <= aux_1 && aux_0 <= aux_2 && aux_0 >= aux_3 && aux_0 >= aux_4) ||
             (aux_0 <= aux_1 && aux_0 <= aux_3 && aux_0 >= aux_2 && aux_0 >= aux_4) ||
             (aux_0 <= aux_1 && aux_0 <= aux_4 && aux_0 >= aux_2 && aux_0 >= aux_3) ||
             (aux_0 <= aux_2 && aux_0 <= aux_3 && aux_0 >= aux_1 && aux_0 >= aux_4) ||
             (aux_0 <= aux_2 && aux_0 <= aux_4 && aux_0 >= aux_1 && aux_0 >= aux_3) ||
             (aux_0 <= aux_3 && aux_0 <= aux_4 && aux_0 >= aux_1 && aux_0 >= aux_2)) {
                meta.meta_k_ary.median = aux_0;
        } 
        else if ((aux_1 <= aux_0 && aux_1 <= aux_2 && aux_1 >= aux_3 && aux_1 >= aux_4) ||
                 (aux_1 <= aux_0 && aux_1 <= aux_3 && aux_1 >= aux_2 && aux_1 >= aux_4) ||
                 (aux_1 <= aux_0 && aux_1 <= aux_4 && aux_1 >= aux_2 && aux_1 >= aux_3) ||
                 (aux_1 <= aux_2 && aux_1 <= aux_3 && aux_1 >= aux_0 && aux_1 >= aux_4) ||
                 (aux_1 <= aux_2 && aux_1 <= aux_4 && aux_1 >= aux_0 && aux_1 >= aux_3) ||
                 (aux_1 <= aux_3 && aux_1 <= aux_4 && aux_1 >= aux_0 && aux_1 >= aux_2)) {
                    meta.meta_k_ary.median = aux_1;
        }
        else if ((aux_2 <= aux_1 && aux_2 <= aux_0 && aux_2 >= aux_3 && aux_2 >= aux_4) ||
                 (aux_2 <= aux_1 && aux_2 <= aux_3 && aux_2 >= aux_0 && aux_2 >= aux_4) ||
                 (aux_2 <= aux_1 && aux_2 <= aux_4 && aux_2 >= aux_0 && aux_2 >= aux_3) ||
                 (aux_2 <= aux_0 && aux_2 <= aux_3 && aux_2 >= aux_1 && aux_2 >= aux_4) ||
                 (aux_2 <= aux_0 && aux_2 <= aux_4 && aux_2 >= aux_1 && aux_2 >= aux_3) ||
                 (aux_2 <= aux_3 && aux_2 <= aux_4 && aux_2 >= aux_1 && aux_2 >= aux_0)) {
                    meta.meta_k_ary.median = aux_2;
        }
        else if ((aux_3 <= aux_1 && aux_3 <= aux_2 && aux_3 >= aux_0 && aux_3 >= aux_4) ||
                 (aux_3 <= aux_1 && aux_3 <= aux_0 && aux_3 >= aux_2 && aux_3 >= aux_4) ||
                 (aux_3 <= aux_1 && aux_3 <= aux_4 && aux_3 >= aux_2 && aux_3 >= aux_0) ||
                 (aux_3 <= aux_2 && aux_3 <= aux_0 && aux_3 >= aux_1 && aux_3 >= aux_4) ||
                 (aux_3 <= aux_2 && aux_3 <= aux_4 && aux_3 >= aux_1 && aux_3 >= aux_0) ||
                 (aux_3 <= aux_0 && aux_3 <= aux_4 && aux_3 >= aux_1 && aux_3 >= aux_2)) {
                    meta.meta_k_ary.median = aux_3;
        }
        else {
            meta.meta_k_ary.median = aux_4;
        }
    }

    action action_k_ary_estimate_row() {

        // Retrieve the current sum of all values.

        k_ary_register_final.read(meta.meta_k_ary.sum, (bit<32>)6);

        // Calculate the estimate for each row.

        meta.meta_k_ary.est_row_0 = (meta.meta_k_ary.sketch_0 - (meta.meta_k_ary.sum / REG_SKETCH_SIZE)) / (1 - (1 / REG_SKETCH_SIZE));
        meta.meta_k_ary.est_row_1 = (meta.meta_k_ary.sketch_1 - (meta.meta_k_ary.sum / REG_SKETCH_SIZE)) / (1 - (1 / REG_SKETCH_SIZE));
        meta.meta_k_ary.est_row_2 = (meta.meta_k_ary.sketch_2 - (meta.meta_k_ary.sum / REG_SKETCH_SIZE)) / (1 - (1 / REG_SKETCH_SIZE));
        meta.meta_k_ary.est_row_3 = (meta.meta_k_ary.sketch_3 - (meta.meta_k_ary.sum / REG_SKETCH_SIZE)) / (1 - (1 / REG_SKETCH_SIZE));
        meta.meta_k_ary.est_row_4 = (meta.meta_k_ary.sketch_4 - (meta.meta_k_ary.sum / REG_SKETCH_SIZE)) / (1 - (1 / REG_SKETCH_SIZE));
    }

    action action_k_ary_estimate_write() {
        k_ary_register_estimate.write((bit<32>)meta.meta_k_ary.hash_0, meta.meta_k_ary.median);
    }

    action action_k_ary_estimate_F2_row() {

        // Retrieve the F2 auxiliary values for each row.

        k_ary_register_final.read(meta.meta_k_ary.est_F2_sum_0, (bit<32>)0);
        k_ary_register_final.read(meta.meta_k_ary.est_F2_sum_1, (bit<32>)1);
        k_ary_register_final.read(meta.meta_k_ary.est_F2_sum_2, (bit<32>)2);
        k_ary_register_final.read(meta.meta_k_ary.est_F2_sum_3, (bit<32>)3);
        k_ary_register_final.read(meta.meta_k_ary.est_F2_sum_4, (bit<32>)4);

        // Retrieve the current sum of all values.

        k_ary_register_final.read(meta.meta_k_ary.sum, (bit<32>)6);

        // Calculate the estimate F2 for each row.

        meta.meta_k_ary.est_F2_row_0 = (REG_SKETCH_SIZE / (REG_SKETCH_SIZE - 1)) * (meta.meta_k_ary.est_F2_sum_0) - (1 / (REG_SKETCH_SIZE - 1)) * (meta.meta_k_ary.sum * meta.meta_k_ary.sum);
        meta.meta_k_ary.est_F2_row_1 = (REG_SKETCH_SIZE / (REG_SKETCH_SIZE - 1)) * (meta.meta_k_ary.est_F2_sum_1) - (1 / (REG_SKETCH_SIZE - 1)) * (meta.meta_k_ary.sum * meta.meta_k_ary.sum);
        meta.meta_k_ary.est_F2_row_2 = (REG_SKETCH_SIZE / (REG_SKETCH_SIZE - 1)) * (meta.meta_k_ary.est_F2_sum_2) - (1 / (REG_SKETCH_SIZE - 1)) * (meta.meta_k_ary.sum * meta.meta_k_ary.sum);
        meta.meta_k_ary.est_F2_row_3 = (REG_SKETCH_SIZE / (REG_SKETCH_SIZE - 1)) * (meta.meta_k_ary.est_F2_sum_3) - (1 / (REG_SKETCH_SIZE - 1)) * (meta.meta_k_ary.sum * meta.meta_k_ary.sum);
        meta.meta_k_ary.est_F2_row_4 = (REG_SKETCH_SIZE / (REG_SKETCH_SIZE - 1)) * (meta.meta_k_ary.est_F2_sum_4) - (1 / (REG_SKETCH_SIZE - 1)) * (meta.meta_k_ary.sum * meta.meta_k_ary.sum);
    }

    action action_k_ary_estimate_F2_write() {
        // When this action is executed, the current median meta value is estimate F2.
        k_ary_register_final.write((bit<32>)5, meta.meta_k_ary.median);
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

    // Table counter used to count packets and bytes matched by each entry of
    // t_l2_fwd table.
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

    // Defines the processing applied by this control block. You can see this as
    // the main function applied to every packet received by the switch.
    apply {
        if (standard_metadata.ingress_port == CPU_PORT) {
            // Packet received from CPU_PORT, this is a packet-out sent by the
            // controller. Skip table processing, set the egress port as
            // requested by the controller (packet_out header) and remove the
            // packet_out header.           
            standard_metadata.egress_spec = hdr.packet_out.egress_port;
            hdr.packet_out.setInvalid();
        } else {
            // Packet received from data plane port.
            // Applies table t_l2_fwd to the packet.
            if (t_l2_fwd.apply().hit) {

                // Check if the current packet is part of a pingall.
                // Only run k-ary's estimate F2 if true.

                action_get_ping_hash();

                if ((bit<32>)meta.meta.ping_hash == (bit<32>)93017) {

                    // Estimate F2
                    
                    action_k_ary_estimate_F2_row();
                    
                    action_k_ary_median(meta.meta_k_ary.est_F2_row_0, 
                                        meta.meta_k_ary.est_F2_row_1,
                                        meta.meta_k_ary.est_F2_row_2,
                                        meta.meta_k_ary.est_F2_row_3,
                                        meta.meta_k_ary.est_F2_row_4);
                    
                    action_k_ary_estimate_F2_write();
                
                } else {

                    // Count-min sketch

                    action_get_cm_hash_0();
                    action_get_cm_hash_1();
                    action_get_cm_hash_2();
                    action_cm_sketch_incr();                
                    
                    meta.meta_cm.sketch_final = meta.meta_cm.sketch_0;
                    
                    if (meta.meta_cm.sketch_final > meta.meta_cm.sketch_1) {
                        meta.meta_cm.sketch_final = meta.meta_cm.sketch_1;
                    }
                    
                    if (meta.meta_cm.sketch_final > meta.meta_cm.sketch_2) {
                        meta.meta_cm.sketch_final = meta.meta_cm.sketch_2;
                    }

                    action_cm_register_write();  
                    
                    // Bitmap sketch

                    action_bm_hash_0();
                    action_bm_hash_1();
                    action_bm_hash_2();                
         
                    // Check the bitmap value for the (ip src, ip dst) pair
                    action_bm_check_pair();

                    if (meta.meta_bm.sketch_0 == 0) {
                        // if the value is 0, we write the bitmap value on register0 and increase the counter
                        // for the ip src on register1 (meaning that we have a new pair)
                        action_bm_new_pair();
                    }

                    // K-ary sketch

                    // Update

                    action_get_k_ary_hash_0();
                    action_get_k_ary_hash_1();
                    action_get_k_ary_hash_2();
                    action_get_k_ary_hash_3();
                    action_get_k_ary_hash_4();

                    action_k_ary_sketch_incr();

                    // Estimate

                    action_k_ary_estimate_row();

                    action_k_ary_median(meta.meta_k_ary.est_row_0, 
                                        meta.meta_k_ary.est_row_1,
                                        meta.meta_k_ary.est_row_2,
                                        meta.meta_k_ary.est_row_3,
                                        meta.meta_k_ary.est_row_4);

                    action_k_ary_estimate_write();                    
                }

                // Packet hit an entry in t_l2_fwd table. A forwarding action
                // has already been taken. No need to apply other tables, exit
                // this control block.                
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