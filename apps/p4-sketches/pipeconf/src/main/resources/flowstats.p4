
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

    register<bit<32>>(131072) cm_register_0;
    register<bit<32>>(131072) cm_register_1;  
    register<bit<32>>(131072) cm_register_2;  
    register<bit<32>>(131072) cm_register_final;
    
    register<bit<32>>(131072) bm_register_0;
    // Bitmap register for the source address.
    register<bit<32>>(131072) bm_register_1;
    // Bitmap register for the destination address.
    register<bit<32>>(131072) bm_register_2;

    register<bit<32>>(131072) k_ary_register_0;
    register<bit<32>>(131072) k_ary_register_1;
    register<bit<32>>(131072) k_ary_register_2;
    register<bit<32>>(131072) k_ary_register_3;
    register<bit<32>>(131072) k_ary_register_4;
    register<bit<32>>(7)      k_ary_register_estimate_F2;

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
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.my_metadata.l4_src_port, (bit<32>)meta.my_metadata.l4_dst_port}, 
            (bit<32>)131072);
        meta.meta_cm.cm_hash_0 = cm_hash_0;
    }

    action action_get_cm_hash_1() {
        hash(cm_hash_1, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.my_metadata.l4_src_port, (bit<32>)meta.my_metadata.l4_dst_port}, 
            (bit<32>)131072);
        meta.meta_cm.cm_hash_1 = cm_hash_1;
    }

    action action_get_cm_hash_2() {
        hash(cm_hash_2, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.my_metadata.l4_src_port, (bit<32>)meta.my_metadata.l4_dst_port},
            (bit<32>)131072);
        meta.meta_cm.cm_hash_2 = cm_hash_2;
    }      

    action action_cm_sketch_incr() {

        cm_register_0.read(meta.meta_cm.cm_sketch_0, (bit<32>)meta.meta_cm.cm_hash_0);
        cm_register_1.read(meta.meta_cm.cm_sketch_1, (bit<32>)meta.meta_cm.cm_hash_1);
        cm_register_2.read(meta.meta_cm.cm_sketch_2, (bit<32>)meta.meta_cm.cm_hash_2);

        meta.meta_cm.cm_sketch_0 = meta.meta_cm.cm_sketch_0 + 1;
        meta.meta_cm.cm_sketch_1 = meta.meta_cm.cm_sketch_1 + 1;
        meta.meta_cm.cm_sketch_2 = meta.meta_cm.cm_sketch_2 + 1;        

        cm_register_0.write((bit<32>)meta.meta_cm.cm_hash_0, meta.meta_cm.cm_sketch_0);
        cm_register_1.write((bit<32>)meta.meta_cm.cm_hash_1, meta.meta_cm.cm_sketch_1);
        cm_register_2.write((bit<32>)meta.meta_cm.cm_hash_2, meta.meta_cm.cm_sketch_2);
    }

    action action_cm_register_write() {
        cm_register_final.write((bit<32>)meta.meta_cm.cm_hash_2, meta.meta_cm.cm_sketch_final);
    }

    // Bitmap sketch actions

    action action_bm_hash_0() {
        hash(bm_hash_0,
            HashAlgorithm.crc32_custom,
            (bit<32>)0,
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.my_metadata.l4_src_port, (bit<32>)meta.my_metadata.l4_dst_port},
            (bit<32>)131072);
        meta.meta_bm.bm_hash_0 = bm_hash_0;
    }

    action action_bm_hash_1() {
        hash(bm_hash_1, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.my_metadata.l4_src_port}, 
            (bit<32>)131072);
        meta.meta_bm.bm_hash_1 = bm_hash_1;
    }

    action action_bm_hash_2() {
        hash(bm_hash_2, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.my_metadata.l4_dst_port}, 
            (bit<32>)131072);
        meta.meta_bm.bm_hash_2 = bm_hash_2;
    }          

    action action_bm_check_pair() {

        // Check the bitmap value for the (ip src, ip dst) pair
        bm_register_0.read(meta.meta_bm.bm_sketch_0, (bit<32>)meta.meta_bm.bm_hash_0);
    }

    action action_bm_new_pair() {
        
        bm_register_1.read(meta.meta_bm.bm_sketch_1, (bit<32>)meta.meta_bm.bm_hash_1);
        bm_register_2.read(meta.meta_bm.bm_sketch_2, (bit<32>)meta.meta_bm.bm_hash_2);

        bm_register_0.write((bit<32>)meta.meta_bm.bm_hash_0, 1);
        bm_register_1.write((bit<32>)meta.meta_bm.bm_hash_1, meta.meta_bm.bm_sketch_1 + 1);
        bm_register_2.write((bit<32>)meta.meta_bm.bm_hash_2, meta.meta_bm.bm_sketch_2 + 1);
    }  

    // K-ary sketch actions

    action action_get_k_ary_hash_0() {
        hash(k_ary_hash_0, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.my_metadata.l4_src_port, (bit<32>)meta.my_metadata.l4_dst_port}, 
            (bit<32>)131072);
        meta.meta_k_ary.k_ary_hash_0 = k_ary_hash_0;
    }

    action action_get_k_ary_hash_1() {
        hash(k_ary_hash_1, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.my_metadata.l4_src_port, (bit<32>)meta.my_metadata.l4_dst_port}, 
            (bit<32>)131072);
        meta.meta_k_ary.k_ary_hash_1 = k_ary_hash_1;
    }

    action action_get_k_ary_hash_2() {
        hash(k_ary_hash_2, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.my_metadata.l4_src_port, (bit<32>)meta.my_metadata.l4_dst_port}, 
            (bit<32>)131072);
        meta.meta_k_ary.k_ary_hash_2 = k_ary_hash_2;
    }

    action action_get_k_ary_hash_3() {
        hash(k_ary_hash_3, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.my_metadata.l4_src_port, (bit<32>)meta.my_metadata.l4_dst_port}, 
            (bit<32>)131072);
        meta.meta_k_ary.k_ary_hash_3 = k_ary_hash_3;
    }

    action action_get_k_ary_hash_4() {
        hash(k_ary_hash_4, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.my_metadata.l4_src_port, (bit<32>)meta.my_metadata.l4_dst_port}, 
            (bit<32>)131072);
        meta.meta_k_ary.k_ary_hash_4 = k_ary_hash_4;
    }

    action action_k_ary_sketch_incr() {

        // Retrieve the current sketch values.

        k_ary_register_0.read(meta.meta_k_ary.k_ary_sketch_0, (bit<32>)meta.meta_k_ary.k_ary_hash_0);
        k_ary_register_1.read(meta.meta_k_ary.k_ary_sketch_1, (bit<32>)meta.meta_k_ary.k_ary_hash_1);
        k_ary_register_2.read(meta.meta_k_ary.k_ary_sketch_2, (bit<32>)meta.meta_k_ary.k_ary_hash_2);
        k_ary_register_3.read(meta.meta_k_ary.k_ary_sketch_3, (bit<32>)meta.meta_k_ary.k_ary_hash_3);
        k_ary_register_4.read(meta.meta_k_ary.k_ary_sketch_4, (bit<32>)meta.meta_k_ary.k_ary_hash_4);

        // Retrieve the current sum of all values.

        k_ary_register_estimate_F2.read(meta.meta_k_ary.k_ary_sum, (bit<32>)6);

        // Retrieve the current values for F2.

        k_ary_register_estimate_F2.read(meta.meta_k_ary.k_ary_sketch_F2_0, (bit<32>)0);
        k_ary_register_estimate_F2.read(meta.meta_k_ary.k_ary_sketch_F2_1, (bit<32>)1); 
        k_ary_register_estimate_F2.read(meta.meta_k_ary.k_ary_sketch_F2_2, (bit<32>)2); 
        k_ary_register_estimate_F2.read(meta.meta_k_ary.k_ary_sketch_F2_3, (bit<32>)3); 
        k_ary_register_estimate_F2.read(meta.meta_k_ary.k_ary_sketch_F2_4, (bit<32>)4);        
        
        // Increase the sketch values.

        meta.meta_k_ary.k_ary_sketch_0 = meta.meta_k_ary.k_ary_sketch_0 + 1;
        meta.meta_k_ary.k_ary_sketch_1 = meta.meta_k_ary.k_ary_sketch_1 + 1;
        meta.meta_k_ary.k_ary_sketch_2 = meta.meta_k_ary.k_ary_sketch_2 + 1;
        meta.meta_k_ary.k_ary_sketch_3 = meta.meta_k_ary.k_ary_sketch_3 + 1;
        meta.meta_k_ary.k_ary_sketch_4 = meta.meta_k_ary.k_ary_sketch_4 + 1;

        // Increase the F2 auxiliary values for each row.

        if (meta.meta_k_ary.k_ary_sketch_F2_0 == 0) {
            meta.meta_k_ary.k_ary_sketch_F2_0 = meta.meta_k_ary.k_ary_sketch_0 * meta.meta_k_ary.k_ary_sketch_0;
        } else {
            meta.meta_k_ary.k_ary_sketch_F2_0 = meta.meta_k_ary.k_ary_sketch_F2_0 - ((meta.meta_k_ary.k_ary_sketch_0 - 1) * (meta.meta_k_ary.k_ary_sketch_0 - 1));
            meta.meta_k_ary.k_ary_sketch_F2_0 = meta.meta_k_ary.k_ary_sketch_F2_0 + (meta.meta_k_ary.k_ary_sketch_0 * meta.meta_k_ary.k_ary_sketch_0);
        }
        if (meta.meta_k_ary.k_ary_sketch_F2_1 == 0) {
            meta.meta_k_ary.k_ary_sketch_F2_1 = meta.meta_k_ary.k_ary_sketch_1 * meta.meta_k_ary.k_ary_sketch_1;
        } else {
            meta.meta_k_ary.k_ary_sketch_F2_1 = meta.meta_k_ary.k_ary_sketch_F2_1 - ((meta.meta_k_ary.k_ary_sketch_1 - 1) * (meta.meta_k_ary.k_ary_sketch_1 - 1));
            meta.meta_k_ary.k_ary_sketch_F2_1 = meta.meta_k_ary.k_ary_sketch_F2_1 + (meta.meta_k_ary.k_ary_sketch_1 * meta.meta_k_ary.k_ary_sketch_1);
        }
        if (meta.meta_k_ary.k_ary_sketch_F2_2 == 0) {
            meta.meta_k_ary.k_ary_sketch_F2_2 = meta.meta_k_ary.k_ary_sketch_2 * meta.meta_k_ary.k_ary_sketch_2;
        } else {
            meta.meta_k_ary.k_ary_sketch_F2_2 = meta.meta_k_ary.k_ary_sketch_F2_2 - ((meta.meta_k_ary.k_ary_sketch_2 - 1) * (meta.meta_k_ary.k_ary_sketch_2 - 1));
            meta.meta_k_ary.k_ary_sketch_F2_2 = meta.meta_k_ary.k_ary_sketch_F2_2 + (meta.meta_k_ary.k_ary_sketch_2 * meta.meta_k_ary.k_ary_sketch_2);
        }
        if (meta.meta_k_ary.k_ary_sketch_F2_3 == 0) {
            meta.meta_k_ary.k_ary_sketch_F2_3 = meta.meta_k_ary.k_ary_sketch_3 * meta.meta_k_ary.k_ary_sketch_3;
        } else {
            meta.meta_k_ary.k_ary_sketch_F2_3 = meta.meta_k_ary.k_ary_sketch_F2_3 - ((meta.meta_k_ary.k_ary_sketch_3 - 1) * (meta.meta_k_ary.k_ary_sketch_3 - 1));
            meta.meta_k_ary.k_ary_sketch_F2_3 = meta.meta_k_ary.k_ary_sketch_F2_3 + (meta.meta_k_ary.k_ary_sketch_3 * meta.meta_k_ary.k_ary_sketch_3);
        }
        if (meta.meta_k_ary.k_ary_sketch_F2_4 == 0) {
            meta.meta_k_ary.k_ary_sketch_F2_4 = meta.meta_k_ary.k_ary_sketch_4 * meta.meta_k_ary.k_ary_sketch_4;
        } else {
            meta.meta_k_ary.k_ary_sketch_F2_4 = meta.meta_k_ary.k_ary_sketch_F2_4 - ((meta.meta_k_ary.k_ary_sketch_4 - 1) * (meta.meta_k_ary.k_ary_sketch_4 - 1));
            meta.meta_k_ary.k_ary_sketch_F2_4 = meta.meta_k_ary.k_ary_sketch_F2_4 + (meta.meta_k_ary.k_ary_sketch_4 * meta.meta_k_ary.k_ary_sketch_4);
        }

        // Update the current sketch values.

        k_ary_register_0.write((bit<32>)meta.meta_k_ary.k_ary_hash_0, meta.meta_k_ary.k_ary_sketch_0);
        k_ary_register_1.write((bit<32>)meta.meta_k_ary.k_ary_hash_1, meta.meta_k_ary.k_ary_sketch_1);
        k_ary_register_2.write((bit<32>)meta.meta_k_ary.k_ary_hash_2, meta.meta_k_ary.k_ary_sketch_2);
        k_ary_register_3.write((bit<32>)meta.meta_k_ary.k_ary_hash_3, meta.meta_k_ary.k_ary_sketch_3);
        k_ary_register_4.write((bit<32>)meta.meta_k_ary.k_ary_hash_4, meta.meta_k_ary.k_ary_sketch_4);

        // Update the current sum of all values.

        k_ary_register_estimate_F2.write((bit<32>)6, meta.meta_k_ary.k_ary_sum + 5);

        // Update the F2 auxiliary values for each row.

        k_ary_register_estimate_F2.write((bit<32>)0, meta.meta_k_ary.k_ary_sketch_F2_0);
        k_ary_register_estimate_F2.write((bit<32>)1, meta.meta_k_ary.k_ary_sketch_F2_1); 
        k_ary_register_estimate_F2.write((bit<32>)2, meta.meta_k_ary.k_ary_sketch_F2_2); 
        k_ary_register_estimate_F2.write((bit<32>)3, meta.meta_k_ary.k_ary_sketch_F2_3); 
        k_ary_register_estimate_F2.write((bit<32>)4, meta.meta_k_ary.k_ary_sketch_F2_4);
    }

    action action_k_ary_sketch_estimate_F2() {
        
        bit<32> tmp0;
        bit<32> tmp1;
        bit<32> tmp2;
        bit<32> tmp3;
        bit<32> tmp4;
        bit<32> tmp5;

        // Retrieve the F2 auxiliary values for each row.

        k_ary_register_estimate_F2.read(meta.meta_k_ary.k_ary_sketch_F2_0, (bit<32>)0);
        k_ary_register_estimate_F2.read(meta.meta_k_ary.k_ary_sketch_F2_1, (bit<32>)1);
        k_ary_register_estimate_F2.read(meta.meta_k_ary.k_ary_sketch_F2_2, (bit<32>)2);
        k_ary_register_estimate_F2.read(meta.meta_k_ary.k_ary_sketch_F2_3, (bit<32>)3);
        k_ary_register_estimate_F2.read(meta.meta_k_ary.k_ary_sketch_F2_4, (bit<32>)4);

        // Retrieve the current sum of all values.

        k_ary_register_estimate_F2.read(meta.meta_k_ary.k_ary_sum, (bit<32>)6);

        // Calculate the estimate F2 for each row.

        meta.meta_k_ary.k_ary_sketch_F2_0 = (131072 / (131072 - 1)) * (meta.meta_k_ary.k_ary_sketch_F2_0) - (1 / (131072 - 1)) * (meta.meta_k_ary.k_ary_sum * meta.meta_k_ary.k_ary_sum);
        meta.meta_k_ary.k_ary_sketch_F2_1 = (131072 / (131072 - 1)) * (meta.meta_k_ary.k_ary_sketch_F2_1) - (1 / (131072 - 1)) * (meta.meta_k_ary.k_ary_sum * meta.meta_k_ary.k_ary_sum);
        meta.meta_k_ary.k_ary_sketch_F2_2 = (131072 / (131072 - 1)) * (meta.meta_k_ary.k_ary_sketch_F2_2) - (1 / (131072 - 1)) * (meta.meta_k_ary.k_ary_sum * meta.meta_k_ary.k_ary_sum);
        meta.meta_k_ary.k_ary_sketch_F2_3 = (131072 / (131072 - 1)) * (meta.meta_k_ary.k_ary_sketch_F2_3) - (1 / (131072 - 1)) * (meta.meta_k_ary.k_ary_sum * meta.meta_k_ary.k_ary_sum);
        meta.meta_k_ary.k_ary_sketch_F2_4 = (131072 / (131072 - 1)) * (meta.meta_k_ary.k_ary_sketch_F2_4) - (1 / (131072 - 1)) * (meta.meta_k_ary.k_ary_sum * meta.meta_k_ary.k_ary_sum);      
    
        // Discover the median value

        if  ((meta.meta_k_ary.k_ary_sketch_F2_0 <= meta.meta_k_ary.k_ary_sketch_F2_1 && meta.meta_k_ary.k_ary_sketch_F2_0 <= meta.meta_k_ary.k_ary_sketch_F2_2 && meta.meta_k_ary.k_ary_sketch_F2_0 >= meta.meta_k_ary.k_ary_sketch_F2_3 && meta.meta_k_ary.k_ary_sketch_F2_0 >= meta.meta_k_ary.k_ary_sketch_F2_4) ||
             (meta.meta_k_ary.k_ary_sketch_F2_0 <= meta.meta_k_ary.k_ary_sketch_F2_1 && meta.meta_k_ary.k_ary_sketch_F2_0 <= meta.meta_k_ary.k_ary_sketch_F2_3 && meta.meta_k_ary.k_ary_sketch_F2_0 >= meta.meta_k_ary.k_ary_sketch_F2_2 && meta.meta_k_ary.k_ary_sketch_F2_0 >= meta.meta_k_ary.k_ary_sketch_F2_4) ||
             (meta.meta_k_ary.k_ary_sketch_F2_0 <= meta.meta_k_ary.k_ary_sketch_F2_1 && meta.meta_k_ary.k_ary_sketch_F2_0 <= meta.meta_k_ary.k_ary_sketch_F2_4 && meta.meta_k_ary.k_ary_sketch_F2_0 >= meta.meta_k_ary.k_ary_sketch_F2_2 && meta.meta_k_ary.k_ary_sketch_F2_0 >= meta.meta_k_ary.k_ary_sketch_F2_3) ||
             (meta.meta_k_ary.k_ary_sketch_F2_0 <= meta.meta_k_ary.k_ary_sketch_F2_2 && meta.meta_k_ary.k_ary_sketch_F2_0 <= meta.meta_k_ary.k_ary_sketch_F2_3 && meta.meta_k_ary.k_ary_sketch_F2_0 >= meta.meta_k_ary.k_ary_sketch_F2_1 && meta.meta_k_ary.k_ary_sketch_F2_0 >= meta.meta_k_ary.k_ary_sketch_F2_4) ||
             (meta.meta_k_ary.k_ary_sketch_F2_0 <= meta.meta_k_ary.k_ary_sketch_F2_2 && meta.meta_k_ary.k_ary_sketch_F2_0 <= meta.meta_k_ary.k_ary_sketch_F2_4 && meta.meta_k_ary.k_ary_sketch_F2_0 >= meta.meta_k_ary.k_ary_sketch_F2_1 && meta.meta_k_ary.k_ary_sketch_F2_0 >= meta.meta_k_ary.k_ary_sketch_F2_3) ||
             (meta.meta_k_ary.k_ary_sketch_F2_0 <= meta.meta_k_ary.k_ary_sketch_F2_3 && meta.meta_k_ary.k_ary_sketch_F2_0 <= meta.meta_k_ary.k_ary_sketch_F2_4 && meta.meta_k_ary.k_ary_sketch_F2_0 >= meta.meta_k_ary.k_ary_sketch_F2_1 && meta.meta_k_ary.k_ary_sketch_F2_0 >= meta.meta_k_ary.k_ary_sketch_F2_2)) {
                meta.meta_k_ary.k_ary_estimate_F2 = meta.meta_k_ary.k_ary_sketch_F2_0;
        } 
        else if ((meta.meta_k_ary.k_ary_sketch_F2_1 <= meta.meta_k_ary.k_ary_sketch_F2_0 && meta.meta_k_ary.k_ary_sketch_F2_1 <= meta.meta_k_ary.k_ary_sketch_F2_2 && meta.meta_k_ary.k_ary_sketch_F2_1 >= meta.meta_k_ary.k_ary_sketch_F2_3 && meta.meta_k_ary.k_ary_sketch_F2_1 >= meta.meta_k_ary.k_ary_sketch_F2_4) ||
                 (meta.meta_k_ary.k_ary_sketch_F2_1 <= meta.meta_k_ary.k_ary_sketch_F2_0 && meta.meta_k_ary.k_ary_sketch_F2_1 <= meta.meta_k_ary.k_ary_sketch_F2_3 && meta.meta_k_ary.k_ary_sketch_F2_1 >= meta.meta_k_ary.k_ary_sketch_F2_2 && meta.meta_k_ary.k_ary_sketch_F2_1 >= meta.meta_k_ary.k_ary_sketch_F2_4) ||
                 (meta.meta_k_ary.k_ary_sketch_F2_1 <= meta.meta_k_ary.k_ary_sketch_F2_0 && meta.meta_k_ary.k_ary_sketch_F2_1 <= meta.meta_k_ary.k_ary_sketch_F2_4 && meta.meta_k_ary.k_ary_sketch_F2_1 >= meta.meta_k_ary.k_ary_sketch_F2_2 && meta.meta_k_ary.k_ary_sketch_F2_1 >= meta.meta_k_ary.k_ary_sketch_F2_3) ||
                 (meta.meta_k_ary.k_ary_sketch_F2_1 <= meta.meta_k_ary.k_ary_sketch_F2_2 && meta.meta_k_ary.k_ary_sketch_F2_1 <= meta.meta_k_ary.k_ary_sketch_F2_3 && meta.meta_k_ary.k_ary_sketch_F2_1 >= meta.meta_k_ary.k_ary_sketch_F2_0 && meta.meta_k_ary.k_ary_sketch_F2_1 >= meta.meta_k_ary.k_ary_sketch_F2_4) ||
                 (meta.meta_k_ary.k_ary_sketch_F2_1 <= meta.meta_k_ary.k_ary_sketch_F2_2 && meta.meta_k_ary.k_ary_sketch_F2_1 <= meta.meta_k_ary.k_ary_sketch_F2_4 && meta.meta_k_ary.k_ary_sketch_F2_1 >= meta.meta_k_ary.k_ary_sketch_F2_0 && meta.meta_k_ary.k_ary_sketch_F2_1 >= meta.meta_k_ary.k_ary_sketch_F2_3) ||
                 (meta.meta_k_ary.k_ary_sketch_F2_1 <= meta.meta_k_ary.k_ary_sketch_F2_3 && meta.meta_k_ary.k_ary_sketch_F2_1 <= meta.meta_k_ary.k_ary_sketch_F2_4 && meta.meta_k_ary.k_ary_sketch_F2_1 >= meta.meta_k_ary.k_ary_sketch_F2_0 && meta.meta_k_ary.k_ary_sketch_F2_1 >= meta.meta_k_ary.k_ary_sketch_F2_2)) {
                    meta.meta_k_ary.k_ary_estimate_F2 = meta.meta_k_ary.k_ary_sketch_F2_1;
        }
        else if ((meta.meta_k_ary.k_ary_sketch_F2_2 <= meta.meta_k_ary.k_ary_sketch_F2_1 && meta.meta_k_ary.k_ary_sketch_F2_2 <= meta.meta_k_ary.k_ary_sketch_F2_0 && meta.meta_k_ary.k_ary_sketch_F2_2 >= meta.meta_k_ary.k_ary_sketch_F2_3 && meta.meta_k_ary.k_ary_sketch_F2_2 >= meta.meta_k_ary.k_ary_sketch_F2_4) ||
                 (meta.meta_k_ary.k_ary_sketch_F2_2 <= meta.meta_k_ary.k_ary_sketch_F2_1 && meta.meta_k_ary.k_ary_sketch_F2_2 <= meta.meta_k_ary.k_ary_sketch_F2_3 && meta.meta_k_ary.k_ary_sketch_F2_2 >= meta.meta_k_ary.k_ary_sketch_F2_0 && meta.meta_k_ary.k_ary_sketch_F2_2 >= meta.meta_k_ary.k_ary_sketch_F2_4) ||
                 (meta.meta_k_ary.k_ary_sketch_F2_2 <= meta.meta_k_ary.k_ary_sketch_F2_1 && meta.meta_k_ary.k_ary_sketch_F2_2 <= meta.meta_k_ary.k_ary_sketch_F2_4 && meta.meta_k_ary.k_ary_sketch_F2_2 >= meta.meta_k_ary.k_ary_sketch_F2_0 && meta.meta_k_ary.k_ary_sketch_F2_2 >= meta.meta_k_ary.k_ary_sketch_F2_3) ||
                 (meta.meta_k_ary.k_ary_sketch_F2_2 <= meta.meta_k_ary.k_ary_sketch_F2_0 && meta.meta_k_ary.k_ary_sketch_F2_2 <= meta.meta_k_ary.k_ary_sketch_F2_3 && meta.meta_k_ary.k_ary_sketch_F2_2 >= meta.meta_k_ary.k_ary_sketch_F2_1 && meta.meta_k_ary.k_ary_sketch_F2_2 >= meta.meta_k_ary.k_ary_sketch_F2_4) ||
                 (meta.meta_k_ary.k_ary_sketch_F2_2 <= meta.meta_k_ary.k_ary_sketch_F2_0 && meta.meta_k_ary.k_ary_sketch_F2_2 <= meta.meta_k_ary.k_ary_sketch_F2_4 && meta.meta_k_ary.k_ary_sketch_F2_2 >= meta.meta_k_ary.k_ary_sketch_F2_1 && meta.meta_k_ary.k_ary_sketch_F2_2 >= meta.meta_k_ary.k_ary_sketch_F2_3) ||
                 (meta.meta_k_ary.k_ary_sketch_F2_2 <= meta.meta_k_ary.k_ary_sketch_F2_3 && meta.meta_k_ary.k_ary_sketch_F2_2 <= meta.meta_k_ary.k_ary_sketch_F2_4 && meta.meta_k_ary.k_ary_sketch_F2_2 >= meta.meta_k_ary.k_ary_sketch_F2_1 && meta.meta_k_ary.k_ary_sketch_F2_2 >= meta.meta_k_ary.k_ary_sketch_F2_0)) {
                    meta.meta_k_ary.k_ary_estimate_F2 = meta.meta_k_ary.k_ary_sketch_F2_2;
        }
        else if ((meta.meta_k_ary.k_ary_sketch_F2_3 <= meta.meta_k_ary.k_ary_sketch_F2_1 && meta.meta_k_ary.k_ary_sketch_F2_3 <= meta.meta_k_ary.k_ary_sketch_F2_2 && meta.meta_k_ary.k_ary_sketch_F2_3 >= meta.meta_k_ary.k_ary_sketch_F2_0 && meta.meta_k_ary.k_ary_sketch_F2_3 >= meta.meta_k_ary.k_ary_sketch_F2_4) ||
                 (meta.meta_k_ary.k_ary_sketch_F2_3 <= meta.meta_k_ary.k_ary_sketch_F2_1 && meta.meta_k_ary.k_ary_sketch_F2_3 <= meta.meta_k_ary.k_ary_sketch_F2_0 && meta.meta_k_ary.k_ary_sketch_F2_3 >= meta.meta_k_ary.k_ary_sketch_F2_2 && meta.meta_k_ary.k_ary_sketch_F2_3 >= meta.meta_k_ary.k_ary_sketch_F2_4) ||
                 (meta.meta_k_ary.k_ary_sketch_F2_3 <= meta.meta_k_ary.k_ary_sketch_F2_1 && meta.meta_k_ary.k_ary_sketch_F2_3 <= meta.meta_k_ary.k_ary_sketch_F2_4 && meta.meta_k_ary.k_ary_sketch_F2_3 >= meta.meta_k_ary.k_ary_sketch_F2_2 && meta.meta_k_ary.k_ary_sketch_F2_3 >= meta.meta_k_ary.k_ary_sketch_F2_0) ||
                 (meta.meta_k_ary.k_ary_sketch_F2_3 <= meta.meta_k_ary.k_ary_sketch_F2_2 && meta.meta_k_ary.k_ary_sketch_F2_3 <= meta.meta_k_ary.k_ary_sketch_F2_0 && meta.meta_k_ary.k_ary_sketch_F2_3 >= meta.meta_k_ary.k_ary_sketch_F2_1 && meta.meta_k_ary.k_ary_sketch_F2_3 >= meta.meta_k_ary.k_ary_sketch_F2_4) ||
                 (meta.meta_k_ary.k_ary_sketch_F2_3 <= meta.meta_k_ary.k_ary_sketch_F2_2 && meta.meta_k_ary.k_ary_sketch_F2_3 <= meta.meta_k_ary.k_ary_sketch_F2_4 && meta.meta_k_ary.k_ary_sketch_F2_3 >= meta.meta_k_ary.k_ary_sketch_F2_1 && meta.meta_k_ary.k_ary_sketch_F2_3 >= meta.meta_k_ary.k_ary_sketch_F2_0) ||
                 (meta.meta_k_ary.k_ary_sketch_F2_3 <= meta.meta_k_ary.k_ary_sketch_F2_0 && meta.meta_k_ary.k_ary_sketch_F2_3 <= meta.meta_k_ary.k_ary_sketch_F2_4 && meta.meta_k_ary.k_ary_sketch_F2_3 >= meta.meta_k_ary.k_ary_sketch_F2_1 && meta.meta_k_ary.k_ary_sketch_F2_3 >= meta.meta_k_ary.k_ary_sketch_F2_2)) {
                    meta.meta_k_ary.k_ary_estimate_F2 = meta.meta_k_ary.k_ary_sketch_F2_3;
        }
        else {
            meta.meta_k_ary.k_ary_estimate_F2 = meta.meta_k_ary.k_ary_sketch_F2_4;
        }

        k_ary_register_estimate_F2.write((bit<32>)5, meta.meta_k_ary.k_ary_estimate_F2);
    }

    // Ping hash.

    action action_get_ping_hash() {
        hash(ping_hash, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr}, 
            (bit<32>)131072);
        meta.my_metadata.ping_hash = ping_hash;
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
                
                // Count-min sketch

                action_get_cm_hash_0();
                action_get_cm_hash_1();
                action_get_cm_hash_2();
                action_cm_sketch_incr();                
                
                meta.meta_cm.cm_sketch_final = meta.meta_cm.cm_sketch_0;
                
                if (meta.meta_cm.cm_sketch_final > meta.meta_cm.cm_sketch_1) {
                    meta.meta_cm.cm_sketch_final = meta.meta_cm.cm_sketch_1;
                }
                
                if (meta.meta_cm.cm_sketch_final > meta.meta_cm.cm_sketch_2) {
                    meta.meta_cm.cm_sketch_final = meta.meta_cm.cm_sketch_2;
                }

                action_cm_register_write();  
                
                // Bitmap sketch

                action_bm_hash_0();
                action_bm_hash_1();
                action_bm_hash_2();                
     
                // Check the bitmap value for the (ip src, ip dst) pair
                action_bm_check_pair();

                if (meta.meta_bm.bm_sketch_0 == 0) {
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

                // Check if the current packet is part of a pingall.
                // Only run both estimates if true.

                action_get_ping_hash();

                if ((bit<32>)meta.my_metadata.ping_hash == (bit<32>)93017) {
                    action_k_ary_sketch_estimate_F2();
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