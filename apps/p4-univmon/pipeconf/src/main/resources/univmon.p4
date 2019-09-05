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

    // Hashes for the sampling phases.
    
    bit<32> binary_hash_1;
    bit<32> binary_hash_2;
    bit<32> binary_hash_3;

    // Hashes for the sketching phases.

    bit<32> count_register_hash_0;
    bit<32> count_register_hash_1;
    bit<32> count_register_hash_2;
    bit<32> count_register_hash_3;

    bit<32> count_update_hash_0;  
    bit<32> count_update_hash_1;
    bit<32> count_update_hash_2;
    bit<32> count_update_hash_3;

    // Hashes for the top-k phases. 

    bit<32> top_k_stage_1_hash;
    bit<32> top_k_stage_2_hash;
    bit<32> top_k_stage_3_hash;

    // Registers for the sketching phases.

    register<bit<32>>(131072) level_0_count_register_0;
    register<bit<32>>(131072) level_0_count_register_1;
    register<bit<32>>(131072) level_0_count_register_2;
    register<bit<32>>(131072) level_0_count_register_3;
    register<bit<32>>(131072) level_0_count_register_final;

    register<bit<32>>(131072) level_1_count_register_0;
    register<bit<32>>(131072) level_1_count_register_1;
    register<bit<32>>(131072) level_1_count_register_2;
    register<bit<32>>(131072) level_1_count_register_3;
    register<bit<32>>(131072) level_1_count_register_final;

    register<bit<32>>(131072) level_2_count_register_0;
    register<bit<32>>(131072) level_2_count_register_1;
    register<bit<32>>(131072) level_2_count_register_2;
    register<bit<32>>(131072) level_2_count_register_3;
    register<bit<32>>(131072) level_2_count_register_final;

    register<bit<32>>(131072) level_3_count_register_0;
    register<bit<32>>(131072) level_3_count_register_1;
    register<bit<32>>(131072) level_3_count_register_2;
    register<bit<32>>(131072) level_3_count_register_3;             
    register<bit<32>>(131072) level_3_count_register_final;

    // Registers for the top-k phases. 

    register<bit<32>>(32) level_0_flow_tracker_stage_1_register;
    register<bit<32>>(32) level_0_flow_tracker_stage_2_register;
    register<bit<32>>(32) level_0_flow_tracker_stage_3_register;
    register<bit<32>>(32) level_0_packet_counter_stage_1_register;
    register<bit<32>>(32) level_0_packet_counter_stage_2_register;
    register<bit<32>>(32) level_0_packet_counter_stage_3_register;
    register<bit<1>>(32)  level_0_valid_bit_stage_1_register;
    register<bit<1>>(32)  level_0_valid_bit_stage_2_register;
    register<bit<1>>(32)  level_0_valid_bit_stage_3_register; 

    register<bit<32>>(32) level_1_flow_tracker_stage_1_register;
    register<bit<32>>(32) level_1_flow_tracker_stage_2_register;
    register<bit<32>>(32) level_1_flow_tracker_stage_3_register;
    register<bit<32>>(32) level_1_packet_counter_stage_1_register;
    register<bit<32>>(32) level_1_packet_counter_stage_2_register;
    register<bit<32>>(32) level_1_packet_counter_stage_3_register;
    register<bit<1>>(32)  level_1_valid_bit_stage_1_register;
    register<bit<1>>(32)  level_1_valid_bit_stage_2_register;
    register<bit<1>>(32)  level_1_valid_bit_stage_3_register; 

    register<bit<32>>(32) level_2_flow_tracker_stage_1_register;
    register<bit<32>>(32) level_2_flow_tracker_stage_2_register;
    register<bit<32>>(32) level_2_flow_tracker_stage_3_register;
    register<bit<32>>(32) level_2_packet_counter_stage_1_register;
    register<bit<32>>(32) level_2_packet_counter_stage_2_register;
    register<bit<32>>(32) level_2_packet_counter_stage_3_register;
    register<bit<1>>(32)  level_2_valid_bit_stage_1_register;
    register<bit<1>>(32)  level_2_valid_bit_stage_2_register;
    register<bit<1>>(32)  level_2_valid_bit_stage_3_register; 

    register<bit<32>>(32) level_3_flow_tracker_stage_1_register;
    register<bit<32>>(32) level_3_flow_tracker_stage_2_register;
    register<bit<32>>(32) level_3_flow_tracker_stage_3_register;
    register<bit<32>>(32) level_3_packet_counter_stage_1_register;
    register<bit<32>>(32) level_3_packet_counter_stage_2_register;
    register<bit<32>>(32) level_3_packet_counter_stage_3_register;
    register<bit<1>>(32)  level_3_valid_bit_stage_1_register;
    register<bit<1>>(32)  level_3_valid_bit_stage_2_register;
    register<bit<1>>(32)  level_3_valid_bit_stage_3_register;             

    // The sampling hashes can have the value 0 or 1,
    // deciding if a specific level is executed for each flow.

    action action_binary_hash_1() {
        hash(binary_hash_1, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.metadata_packet.l4_src_port, (bit<32>)meta.metadata_packet.l4_dst_port},
            (bit<32>)2);
        meta.metadata_packet.binary_hash_1 = binary_hash_1;
    }

    action action_binary_hash_2() {
        hash(binary_hash_2, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.metadata_packet.l4_src_port, (bit<32>)meta.metadata_packet.l4_dst_port},
            (bit<32>)2);
        meta.metadata_packet.binary_hash_2 = binary_hash_2;
    }

    action action_binary_hash_3() {
        hash(binary_hash_3, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.metadata_packet.l4_src_port, (bit<32>)meta.metadata_packet.l4_dst_port},
            (bit<32>)2);
        meta.metadata_packet.binary_hash_3 = binary_hash_3;
    }    

    action action_count_register_hash_0() {
        hash(count_register_hash_0, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.metadata_packet.l4_src_port, (bit<32>)meta.metadata_packet.l4_dst_port},
            (bit<32>)131072);
        meta.metadata_packet.count_register_hash_0 = count_register_hash_0;
    }

    action action_count_register_hash_1() {
        hash(count_register_hash_1, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.metadata_packet.l4_src_port, (bit<32>)meta.metadata_packet.l4_dst_port},
            (bit<32>)131072);
        meta.metadata_packet.count_register_hash_1 = count_register_hash_1;
    }

    action action_count_register_hash_2() {
        hash(count_register_hash_2, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.metadata_packet.l4_src_port, (bit<32>)meta.metadata_packet.l4_dst_port},
            (bit<32>)131072);
        meta.metadata_packet.count_register_hash_2 = count_register_hash_2;
    }

    action action_count_register_hash_3() {
        hash(count_register_hash_3, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.metadata_packet.l4_src_port, (bit<32>)meta.metadata_packet.l4_dst_port},
            (bit<32>)131072);
        meta.metadata_packet.count_register_hash_3 = count_register_hash_3;
    }

    action action_count_update_hash_0() {
        hash(count_update_hash_0, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.metadata_packet.l4_src_port, (bit<32>)meta.metadata_packet.l4_dst_port},
            (bit<32>)2);
        meta.metadata_packet.count_update_hash_0 = count_update_hash_0;
    }

    action action_count_update_hash_1() {
        hash(count_update_hash_1, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.metadata_packet.l4_src_port, (bit<32>)meta.metadata_packet.l4_dst_port},
            (bit<32>)2);
        meta.metadata_packet.count_update_hash_1 = count_update_hash_1;
    }

    action action_count_update_hash_2() {
        hash(count_update_hash_2, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.metadata_packet.l4_src_port, (bit<32>)meta.metadata_packet.l4_dst_port}, 
            (bit<32>)2);
        meta.metadata_packet.count_update_hash_2 = count_update_hash_2;
    }

    action action_count_update_hash_3() {
        hash(count_update_hash_3, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.metadata_packet.l4_src_port, (bit<32>)meta.metadata_packet.l4_dst_port},
            (bit<32>)2);
        meta.metadata_packet.count_update_hash_3 = count_update_hash_3;
    }

    action action_top_k_stage_1_hash() {
        hash(top_k_stage_1_hash, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.metadata_packet.l4_src_port, (bit<32>)meta.metadata_packet.l4_dst_port},
            (bit<32>)32);
        meta.metadata_tracking.mIndex1 = top_k_stage_1_hash;
    }

    action action_top_k_stage_2_hash() {
        hash(top_k_stage_2_hash, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.metadata_packet.l4_src_port, (bit<32>)meta.metadata_packet.l4_dst_port},
            (bit<32>)32);
        meta.metadata_tracking.mIndex2 = top_k_stage_2_hash;
    }

    action action_top_k_stage_3_hash() {
        hash(top_k_stage_3_hash, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.metadata_packet.l4_src_port, (bit<32>)meta.metadata_packet.l4_dst_port},
            (bit<32>)32);
        meta.metadata_tracking.mIndex3 = top_k_stage_3_hash;
    }    

    action action_level_0_count_sketch_incr() {      
        
        bit<32> tmp_0;
        bit<32> tmp_1;
        bit<32> tmp_2;
        bit<32> tmp_3;

        level_0_count_register_0.read(tmp_0, meta.metadata_packet.count_register_hash_0);
        level_0_count_register_1.read(tmp_1, meta.metadata_packet.count_register_hash_1);
        level_0_count_register_2.read(tmp_2, meta.metadata_packet.count_register_hash_2);
        level_0_count_register_3.read(tmp_3, meta.metadata_packet.count_register_hash_3);

        meta.metadata_packet.packet_counter_0 = tmp_0;
        meta.metadata_packet.packet_counter_1 = tmp_1;
        meta.metadata_packet.packet_counter_2 = tmp_2;
        meta.metadata_packet.packet_counter_3 = tmp_3;

        if (meta.metadata_packet.count_update_hash_0 == 0) {
            meta.metadata_packet.packet_counter_0 = meta.metadata_packet.packet_counter_0 - 1;
        } else {
            meta.metadata_packet.packet_counter_0 = meta.metadata_packet.packet_counter_0 + 1;
        }

        if (meta.metadata_packet.count_update_hash_1 == 0) {
            meta.metadata_packet.packet_counter_1 = meta.metadata_packet.packet_counter_1 - 1;
        } else {
            meta.metadata_packet.packet_counter_1 = meta.metadata_packet.packet_counter_1 + 1;
        }

        if (meta.metadata_packet.count_update_hash_2 == 0) {
            meta.metadata_packet.packet_counter_2 = meta.metadata_packet.packet_counter_2 - 1;
        } else {
            meta.metadata_packet.packet_counter_2 = meta.metadata_packet.packet_counter_2 + 1;
        }

        if (meta.metadata_packet.count_update_hash_3 == 0) {
            meta.metadata_packet.packet_counter_3 = meta.metadata_packet.packet_counter_3 - 1;
        } else {
            meta.metadata_packet.packet_counter_3 = meta.metadata_packet.packet_counter_3 + 1;
        }                        

        level_0_count_register_0.write(meta.metadata_packet.count_register_hash_0, meta.metadata_packet.packet_counter_0);
        level_0_count_register_1.write(meta.metadata_packet.count_register_hash_1, meta.metadata_packet.packet_counter_1);
        level_0_count_register_2.write(meta.metadata_packet.count_register_hash_2, meta.metadata_packet.packet_counter_2);
        level_0_count_register_3.write(meta.metadata_packet.count_register_hash_3, meta.metadata_packet.packet_counter_3);

        tmp_0 = meta.metadata_packet.packet_counter_0;
        tmp_1 = meta.metadata_packet.packet_counter_1;
        tmp_2 = meta.metadata_packet.packet_counter_2;
        tmp_3 = meta.metadata_packet.packet_counter_3;

        if  ((tmp_0 <= tmp_1 && tmp_0 <= tmp_2 && tmp_0 >= tmp_3) ||
            (tmp_0 <= tmp_1 && tmp_0 <= tmp_3 && tmp_0 >= tmp_2) ||
            (tmp_0 <= tmp_1 && tmp_0 >= tmp_2 && tmp_0 >= tmp_3) ||
            (tmp_0 <= tmp_2 && tmp_0 <= tmp_3 && tmp_0 >= tmp_1) ||
            (tmp_0 <= tmp_2 && tmp_0 >= tmp_1 && tmp_0 >= tmp_3) ||
            (tmp_0 <= tmp_3 && tmp_0 >= tmp_1 && tmp_0 >= tmp_2)) {
                meta.metadata_packet.count_final_val = tmp_0;
        } 
        else if ((tmp_1 <= tmp_0 && tmp_1 <= tmp_2 && tmp_1 >= tmp_3) ||
                (tmp_1 <= tmp_0 && tmp_1 <= tmp_3 && tmp_1 >= tmp_2) ||
                (tmp_1 <= tmp_0 && tmp_1 >= tmp_2 && tmp_1 >= tmp_3) ||
                (tmp_1 <= tmp_2 && tmp_1 <= tmp_3 && tmp_1 >= tmp_0) ||
                (tmp_1 <= tmp_2 && tmp_1 >= tmp_0 && tmp_1 >= tmp_3) ||
                (tmp_1 <= tmp_3 && tmp_1 >= tmp_0 && tmp_1 >= tmp_2)) {
                    meta.metadata_packet.count_final_val = tmp_1;
        }
        else if ((tmp_2 <= tmp_1 && tmp_2 <= tmp_0 && tmp_2 >= tmp_3) ||
                (tmp_2 <= tmp_1 && tmp_2 <= tmp_3 && tmp_2 >= tmp_0) ||
                (tmp_2 <= tmp_1 && tmp_2 >= tmp_0 && tmp_2 >= tmp_3) ||
                (tmp_2 <= tmp_0 && tmp_2 <= tmp_3 && tmp_2 >= tmp_1) ||
                (tmp_2 <= tmp_0 && tmp_2 >= tmp_1 && tmp_2 >= tmp_3) ||
                (tmp_2 <= tmp_3 && tmp_2 >= tmp_1 && tmp_2 >= tmp_0)) {
                    meta.metadata_packet.count_final_val = tmp_2;
        }
        else {
             meta.metadata_packet.count_final_val = tmp_3;
        }

        level_0_count_register_final.write(meta.metadata_packet.count_register_hash_0, meta.metadata_packet.count_final_val);
    } 

    action action_level_1_count_sketch_incr() {      
        
        bit<32> tmp_0;
        bit<32> tmp_1;
        bit<32> tmp_2;
        bit<32> tmp_3;

        level_1_count_register_0.read(tmp_0, meta.metadata_packet.count_register_hash_0);
        level_1_count_register_1.read(tmp_1, meta.metadata_packet.count_register_hash_1);
        level_1_count_register_2.read(tmp_2, meta.metadata_packet.count_register_hash_2);
        level_1_count_register_3.read(tmp_3, meta.metadata_packet.count_register_hash_3);

        meta.metadata_packet.packet_counter_0 = tmp_0;
        meta.metadata_packet.packet_counter_1 = tmp_1;
        meta.metadata_packet.packet_counter_2 = tmp_2;
        meta.metadata_packet.packet_counter_3 = tmp_3;

        if (meta.metadata_packet.count_update_hash_0 == 0) {
            meta.metadata_packet.packet_counter_0 = meta.metadata_packet.packet_counter_0 - 1;
        } else {
            meta.metadata_packet.packet_counter_0 = meta.metadata_packet.packet_counter_0 + 1;
        }

        if (meta.metadata_packet.count_update_hash_1 == 0) {
            meta.metadata_packet.packet_counter_1 = meta.metadata_packet.packet_counter_1 - 1;
        } else {
            meta.metadata_packet.packet_counter_1 = meta.metadata_packet.packet_counter_1 + 1;
        }

        if (meta.metadata_packet.count_update_hash_2 == 0) {
            meta.metadata_packet.packet_counter_2 = meta.metadata_packet.packet_counter_2 - 1;
        } else {
            meta.metadata_packet.packet_counter_2 = meta.metadata_packet.packet_counter_2 + 1;
        }

        if (meta.metadata_packet.count_update_hash_3 == 0) {
            meta.metadata_packet.packet_counter_3 = meta.metadata_packet.packet_counter_3 - 1;
        } else {
            meta.metadata_packet.packet_counter_3 = meta.metadata_packet.packet_counter_3 + 1;
        }                        

        level_1_count_register_0.write(meta.metadata_packet.count_register_hash_0, meta.metadata_packet.packet_counter_0);
        level_1_count_register_1.write(meta.metadata_packet.count_register_hash_1, meta.metadata_packet.packet_counter_1);
        level_1_count_register_2.write(meta.metadata_packet.count_register_hash_2, meta.metadata_packet.packet_counter_2);
        level_1_count_register_3.write(meta.metadata_packet.count_register_hash_3, meta.metadata_packet.packet_counter_3);

        tmp_0 = meta.metadata_packet.packet_counter_0;
        tmp_1 = meta.metadata_packet.packet_counter_1;
        tmp_2 = meta.metadata_packet.packet_counter_2;
        tmp_3 = meta.metadata_packet.packet_counter_3;

        if  ((tmp_0 <= tmp_1 && tmp_0 <= tmp_2 && tmp_0 >= tmp_3) ||
            (tmp_0 <= tmp_1 && tmp_0 <= tmp_3 && tmp_0 >= tmp_2) ||
            (tmp_0 <= tmp_1 && tmp_0 >= tmp_2 && tmp_0 >= tmp_3) ||
            (tmp_0 <= tmp_2 && tmp_0 <= tmp_3 && tmp_0 >= tmp_1) ||
            (tmp_0 <= tmp_2 && tmp_0 >= tmp_1 && tmp_0 >= tmp_3) ||
            (tmp_0 <= tmp_3 && tmp_0 >= tmp_1 && tmp_0 >= tmp_2)) {
                meta.metadata_packet.count_final_val = tmp_0;
        } 
        else if ((tmp_1 <= tmp_0 && tmp_1 <= tmp_2 && tmp_1 >= tmp_3) ||
                (tmp_1 <= tmp_0 && tmp_1 <= tmp_3 && tmp_1 >= tmp_2) ||
                (tmp_1 <= tmp_0 && tmp_1 >= tmp_2 && tmp_1 >= tmp_3) ||
                (tmp_1 <= tmp_2 && tmp_1 <= tmp_3 && tmp_1 >= tmp_0) ||
                (tmp_1 <= tmp_2 && tmp_1 >= tmp_0 && tmp_1 >= tmp_3) ||
                (tmp_1 <= tmp_3 && tmp_1 >= tmp_0 && tmp_1 >= tmp_2)) {
                    meta.metadata_packet.count_final_val = tmp_1;
        }
        else if ((tmp_2 <= tmp_1 && tmp_2 <= tmp_0 && tmp_2 >= tmp_3) ||
                (tmp_2 <= tmp_1 && tmp_2 <= tmp_3 && tmp_2 >= tmp_0) ||
                (tmp_2 <= tmp_1 && tmp_2 >= tmp_0 && tmp_2 >= tmp_3) ||
                (tmp_2 <= tmp_0 && tmp_2 <= tmp_3 && tmp_2 >= tmp_1) ||
                (tmp_2 <= tmp_0 && tmp_2 >= tmp_1 && tmp_2 >= tmp_3) ||
                (tmp_2 <= tmp_3 && tmp_2 >= tmp_1 && tmp_2 >= tmp_0)) {
                    meta.metadata_packet.count_final_val = tmp_2;
        }
        else {
             meta.metadata_packet.count_final_val = tmp_3;
        }

        level_1_count_register_final.write(meta.metadata_packet.count_register_hash_0, meta.metadata_packet.count_final_val);
    }

    action action_level_2_count_sketch_incr() {      
        
        bit<32> tmp_0;
        bit<32> tmp_1;
        bit<32> tmp_2;
        bit<32> tmp_3;

        level_2_count_register_0.read(tmp_0, meta.metadata_packet.count_register_hash_0);
        level_2_count_register_1.read(tmp_1, meta.metadata_packet.count_register_hash_1);
        level_2_count_register_2.read(tmp_2, meta.metadata_packet.count_register_hash_2);
        level_2_count_register_3.read(tmp_3, meta.metadata_packet.count_register_hash_3);

        meta.metadata_packet.packet_counter_0 = tmp_0;
        meta.metadata_packet.packet_counter_1 = tmp_1;
        meta.metadata_packet.packet_counter_2 = tmp_2;
        meta.metadata_packet.packet_counter_3 = tmp_3;

        if (meta.metadata_packet.count_update_hash_0 == 0) {
            meta.metadata_packet.packet_counter_0 = meta.metadata_packet.packet_counter_0 - 1;
        } else {
            meta.metadata_packet.packet_counter_0 = meta.metadata_packet.packet_counter_0 + 1;
        }

        if (meta.metadata_packet.count_update_hash_1 == 0) {
            meta.metadata_packet.packet_counter_1 = meta.metadata_packet.packet_counter_1 - 1;
        } else {
            meta.metadata_packet.packet_counter_1 = meta.metadata_packet.packet_counter_1 + 1;
        }

        if (meta.metadata_packet.count_update_hash_2 == 0) {
            meta.metadata_packet.packet_counter_2 = meta.metadata_packet.packet_counter_2 - 1;
        } else {
            meta.metadata_packet.packet_counter_2 = meta.metadata_packet.packet_counter_2 + 1;
        }

        if (meta.metadata_packet.count_update_hash_3 == 0) {
            meta.metadata_packet.packet_counter_3 = meta.metadata_packet.packet_counter_3 - 1;
        } else {
            meta.metadata_packet.packet_counter_3 = meta.metadata_packet.packet_counter_3 + 1;
        }                        

        level_2_count_register_0.write(meta.metadata_packet.count_register_hash_0, meta.metadata_packet.packet_counter_0);
        level_2_count_register_1.write(meta.metadata_packet.count_register_hash_1, meta.metadata_packet.packet_counter_1);
        level_2_count_register_2.write(meta.metadata_packet.count_register_hash_2, meta.metadata_packet.packet_counter_2);
        level_2_count_register_3.write(meta.metadata_packet.count_register_hash_3, meta.metadata_packet.packet_counter_3);

        tmp_0 = meta.metadata_packet.packet_counter_0;
        tmp_1 = meta.metadata_packet.packet_counter_1;
        tmp_2 = meta.metadata_packet.packet_counter_2;
        tmp_3 = meta.metadata_packet.packet_counter_3;

        if  ((tmp_0 <= tmp_1 && tmp_0 <= tmp_2 && tmp_0 >= tmp_3) ||
            (tmp_0 <= tmp_1 && tmp_0 <= tmp_3 && tmp_0 >= tmp_2) ||
            (tmp_0 <= tmp_1 && tmp_0 >= tmp_2 && tmp_0 >= tmp_3) ||
            (tmp_0 <= tmp_2 && tmp_0 <= tmp_3 && tmp_0 >= tmp_1) ||
            (tmp_0 <= tmp_2 && tmp_0 >= tmp_1 && tmp_0 >= tmp_3) ||
            (tmp_0 <= tmp_3 && tmp_0 >= tmp_1 && tmp_0 >= tmp_2)) {
                meta.metadata_packet.count_final_val = tmp_0;
        } 
        else if ((tmp_1 <= tmp_0 && tmp_1 <= tmp_2 && tmp_1 >= tmp_3) ||
                (tmp_1 <= tmp_0 && tmp_1 <= tmp_3 && tmp_1 >= tmp_2) ||
                (tmp_1 <= tmp_0 && tmp_1 >= tmp_2 && tmp_1 >= tmp_3) ||
                (tmp_1 <= tmp_2 && tmp_1 <= tmp_3 && tmp_1 >= tmp_0) ||
                (tmp_1 <= tmp_2 && tmp_1 >= tmp_0 && tmp_1 >= tmp_3) ||
                (tmp_1 <= tmp_3 && tmp_1 >= tmp_0 && tmp_1 >= tmp_2)) {
                    meta.metadata_packet.count_final_val = tmp_1;
        }
        else if ((tmp_2 <= tmp_1 && tmp_2 <= tmp_0 && tmp_2 >= tmp_3) ||
                (tmp_2 <= tmp_1 && tmp_2 <= tmp_3 && tmp_2 >= tmp_0) ||
                (tmp_2 <= tmp_1 && tmp_2 >= tmp_0 && tmp_2 >= tmp_3) ||
                (tmp_2 <= tmp_0 && tmp_2 <= tmp_3 && tmp_2 >= tmp_1) ||
                (tmp_2 <= tmp_0 && tmp_2 >= tmp_1 && tmp_2 >= tmp_3) ||
                (tmp_2 <= tmp_3 && tmp_2 >= tmp_1 && tmp_2 >= tmp_0)) {
                    meta.metadata_packet.count_final_val = tmp_2;
        }
        else {
             meta.metadata_packet.count_final_val = tmp_3;
        }

        level_2_count_register_final.write(meta.metadata_packet.count_register_hash_0, meta.metadata_packet.count_final_val);
    }

    action action_level_3_count_sketch_incr() {      
        
        bit<32> tmp_0;
        bit<32> tmp_1;
        bit<32> tmp_2;
        bit<32> tmp_3;

        level_3_count_register_0.read(tmp_0, meta.metadata_packet.count_register_hash_0);
        level_3_count_register_1.read(tmp_1, meta.metadata_packet.count_register_hash_1);
        level_3_count_register_2.read(tmp_2, meta.metadata_packet.count_register_hash_2);
        level_3_count_register_3.read(tmp_3, meta.metadata_packet.count_register_hash_3);

        meta.metadata_packet.packet_counter_0 = tmp_0;
        meta.metadata_packet.packet_counter_1 = tmp_1;
        meta.metadata_packet.packet_counter_2 = tmp_2;
        meta.metadata_packet.packet_counter_3 = tmp_3;

        if (meta.metadata_packet.count_update_hash_0 == 0) {
            meta.metadata_packet.packet_counter_0 = meta.metadata_packet.packet_counter_0 - 1;
        } else {
            meta.metadata_packet.packet_counter_0 = meta.metadata_packet.packet_counter_0 + 1;
        }

        if (meta.metadata_packet.count_update_hash_1 == 0) {
            meta.metadata_packet.packet_counter_1 = meta.metadata_packet.packet_counter_1 - 1;
        } else {
            meta.metadata_packet.packet_counter_1 = meta.metadata_packet.packet_counter_1 + 1;
        }

        if (meta.metadata_packet.count_update_hash_2 == 0) {
            meta.metadata_packet.packet_counter_2 = meta.metadata_packet.packet_counter_2 - 1;
        } else {
            meta.metadata_packet.packet_counter_2 = meta.metadata_packet.packet_counter_2 + 1;
        }

        if (meta.metadata_packet.count_update_hash_3 == 0) {
            meta.metadata_packet.packet_counter_3 = meta.metadata_packet.packet_counter_3 - 1;
        } else {
            meta.metadata_packet.packet_counter_3 = meta.metadata_packet.packet_counter_3 + 1;
        }                        

        level_3_count_register_0.write(meta.metadata_packet.count_register_hash_0, meta.metadata_packet.packet_counter_0);
        level_3_count_register_1.write(meta.metadata_packet.count_register_hash_1, meta.metadata_packet.packet_counter_1);
        level_3_count_register_2.write(meta.metadata_packet.count_register_hash_2, meta.metadata_packet.packet_counter_2);
        level_3_count_register_3.write(meta.metadata_packet.count_register_hash_3, meta.metadata_packet.packet_counter_3);

        tmp_0 = meta.metadata_packet.packet_counter_0;
        tmp_1 = meta.metadata_packet.packet_counter_1;
        tmp_2 = meta.metadata_packet.packet_counter_2;
        tmp_3 = meta.metadata_packet.packet_counter_3;

        if  ((tmp_0 <= tmp_1 && tmp_0 <= tmp_2 && tmp_0 >= tmp_3) ||
            (tmp_0 <= tmp_1 && tmp_0 <= tmp_3 && tmp_0 >= tmp_2) ||
            (tmp_0 <= tmp_1 && tmp_0 >= tmp_2 && tmp_0 >= tmp_3) ||
            (tmp_0 <= tmp_2 && tmp_0 <= tmp_3 && tmp_0 >= tmp_1) ||
            (tmp_0 <= tmp_2 && tmp_0 >= tmp_1 && tmp_0 >= tmp_3) ||
            (tmp_0 <= tmp_3 && tmp_0 >= tmp_1 && tmp_0 >= tmp_2)) {
                meta.metadata_packet.count_final_val = tmp_0;
        } 
        else if ((tmp_1 <= tmp_0 && tmp_1 <= tmp_2 && tmp_1 >= tmp_3) ||
                (tmp_1 <= tmp_0 && tmp_1 <= tmp_3 && tmp_1 >= tmp_2) ||
                (tmp_1 <= tmp_0 && tmp_1 >= tmp_2 && tmp_1 >= tmp_3) ||
                (tmp_1 <= tmp_2 && tmp_1 <= tmp_3 && tmp_1 >= tmp_0) ||
                (tmp_1 <= tmp_2 && tmp_1 >= tmp_0 && tmp_1 >= tmp_3) ||
                (tmp_1 <= tmp_3 && tmp_1 >= tmp_0 && tmp_1 >= tmp_2)) {
                    meta.metadata_packet.count_final_val = tmp_1;
        }
        else if ((tmp_2 <= tmp_1 && tmp_2 <= tmp_0 && tmp_2 >= tmp_3) ||
                (tmp_2 <= tmp_1 && tmp_2 <= tmp_3 && tmp_2 >= tmp_0) ||
                (tmp_2 <= tmp_1 && tmp_2 >= tmp_0 && tmp_2 >= tmp_3) ||
                (tmp_2 <= tmp_0 && tmp_2 <= tmp_3 && tmp_2 >= tmp_1) ||
                (tmp_2 <= tmp_0 && tmp_2 >= tmp_1 && tmp_2 >= tmp_3) ||
                (tmp_2 <= tmp_3 && tmp_2 >= tmp_1 && tmp_2 >= tmp_0)) {
                    meta.metadata_packet.count_final_val = tmp_2;
        }
        else {
             meta.metadata_packet.count_final_val = tmp_3;
        }

        level_3_count_register_final.write(meta.metadata_packet.count_register_hash_0, meta.metadata_packet.count_final_val);
    }

    action action_level_0_top_k_stage_1() { 

        bit<32> tmp_0;
        bit<32> tmp_1;
        bit<1>  tmp_2;

        // First table stage.
        // meta.metadata_tracking.mKeyCarried   = hdr.ipv4.src_addr;
        
        meta.metadata_tracking.mKeyCarried   = meta.metadata_packet.count_register_hash_0;
        meta.metadata_tracking.mCountCarried = 0;
        
        // Read the key and value at that location.
        
        level_0_flow_tracker_stage_1_register.read(tmp_0, meta.metadata_tracking.mIndex1);
        level_0_packet_counter_stage_1_register.read(tmp_1, meta.metadata_tracking.mIndex1);
        level_0_valid_bit_stage_1_register.read(tmp_2, meta.metadata_tracking.mIndex1);       
        
        meta.metadata_tracking.mKeyInTable      = tmp_0;
        meta.metadata_tracking.mCountInTable    = tmp_1;
        meta.metadata_tracking.mValid           = tmp_2;

        // Check if location is empty or has a different key in there.
        
        if (meta.metadata_tracking.mValid == 0) {
            meta.metadata_tracking.mKeyInTable = meta.metadata_tracking.mKeyCarried;
        } else {
            meta.metadata_tracking.mKeyInTable = meta.metadata_tracking.mKeyInTable;
        }

        if (meta.metadata_tracking.mValid == 0) {
            meta.metadata_tracking.mSwapSpace = 0;
        } else {
            meta.metadata_tracking.mSwapSpace = meta.metadata_tracking.mKeyInTable - meta.metadata_tracking.mKeyCarried;    
        }

        // Update hash table.

        level_0_flow_tracker_stage_1_register.write(meta.metadata_tracking.mIndex1, meta.metadata_tracking.mKeyCarried);
        
        if (meta.metadata_tracking.mSwapSpace == 0) {
            tmp_1 = meta.metadata_tracking.mCountInTable + 1;
        } else {
            tmp_1 = 1;
        }
        level_0_packet_counter_stage_1_register.write(meta.metadata_tracking.mIndex1, tmp_1);
        
        level_0_valid_bit_stage_1_register.write(meta.metadata_tracking.mIndex1, 1);

        // Update metadata carried to the next table stage.

        if (meta.metadata_tracking.mSwapSpace == 0) {
            meta.metadata_tracking.mKeyCarried = 0;
        } else {
            meta.metadata_tracking.mKeyCarried = meta.metadata_tracking.mKeyInTable;
        }
        
        if (meta.metadata_tracking.mSwapSpace == 0) {
            meta.metadata_tracking.mCountCarried = 0;
        } else {
            meta.metadata_tracking.mCountCarried = meta.metadata_tracking.mCountInTable;
        }        
    }

    action action_level_0_top_k_stage_2() {

        bit<32> tmp_0;
        bit<32> tmp_1;
        bit<1>  tmp_2;        

        // Read the key and value at that location.

        level_0_flow_tracker_stage_2_register.read(tmp_0, meta.metadata_tracking.mIndex2);
        level_0_packet_counter_stage_2_register.read(tmp_1, meta.metadata_tracking.mIndex2);
        level_0_valid_bit_stage_2_register.read(tmp_2, meta.metadata_tracking.mIndex2);       
        
        meta.metadata_tracking.mKeyInTable      = tmp_0;
        meta.metadata_tracking.mCountInTable    = tmp_1;
        meta.metadata_tracking.mValid           = tmp_2;

        // Check if location is empty or has a different key in there.

        if (meta.metadata_tracking.mValid == 0) {
            meta.metadata_tracking.mKeyInTable = meta.metadata_tracking.mKeyCarried;
        } else {
            meta.metadata_tracking.mKeyInTable = meta.metadata_tracking.mKeyInTable;
        }

        if (meta.metadata_tracking.mValid == 0) {
            meta.metadata_tracking.mSwapSpace = 0;
        } else {
            meta.metadata_tracking.mSwapSpace = meta.metadata_tracking.mKeyInTable - meta.metadata_tracking.mKeyCarried;
        }

        // Update hash table.

        if (meta.metadata_tracking.mSwapSpace == 0) {
            tmp_0 = meta.metadata_tracking.mKeyInTable;
        } else if (meta.metadata_tracking.mCountInTable < meta.metadata_tracking.mCountCarried) {
            tmp_0 = meta.metadata_tracking.mKeyCarried;
        } else {
            tmp_0 = meta.metadata_tracking.mKeyInTable;
        }

        level_0_flow_tracker_stage_2_register.write(meta.metadata_tracking.mIndex2, tmp_0);

        if (meta.metadata_tracking.mSwapSpace == 0) {
            tmp_1 = meta.metadata_tracking.mCountInTable + meta.metadata_tracking.mCountCarried;
        } else if (meta.metadata_tracking.mCountInTable < meta.metadata_tracking.mCountCarried) {
            tmp_1 = meta.metadata_tracking.mCountCarried;
        } else {
            tmp_1 = meta.metadata_tracking.mCountInTable;
        }

        level_0_packet_counter_stage_2_register.write(meta.metadata_tracking.mIndex2, tmp_1);        

        if (meta.metadata_tracking.mValid == 0) {
            if (meta.metadata_tracking.mKeyCarried == 0) {
                tmp_2 = 0;
            } else {
                tmp_2 = 1;
            }
        } else {
            tmp_2 = 1;
        }

        level_0_valid_bit_stage_2_register.write(meta.metadata_tracking.mIndex2, tmp_2);

        // Update metadata carried to the next table stage.

        if (meta.metadata_tracking.mSwapSpace == 0) {
            meta.metadata_tracking.mKeyCarried = 0;
        } else {
            meta.metadata_tracking.mKeyCarried = meta.metadata_tracking.mKeyInTable;
        }

        if (meta.metadata_tracking.mSwapSpace == 0) {
            meta.metadata_tracking.mCountCarried = 0;
        } else {
            meta.metadata_tracking.mCountCarried = meta.metadata_tracking.mCountInTable;
        }        
    }

    action action_level_0_top_k_stage_3() {

        bit<32> tmp_0;
        bit<32> tmp_1;
        bit<1>  tmp_2;        

        // Read the key and value at that location.

        level_0_flow_tracker_stage_3_register.read(tmp_0, meta.metadata_tracking.mIndex3);
        level_0_packet_counter_stage_3_register.read(tmp_1, meta.metadata_tracking.mIndex3);
        level_0_valid_bit_stage_3_register.read(tmp_2, meta.metadata_tracking.mIndex3);       
        
        meta.metadata_tracking.mKeyInTable      = tmp_0;
        meta.metadata_tracking.mCountInTable    = tmp_1;
        meta.metadata_tracking.mValid           = tmp_2;

        // Check if location is empty or has a different key in there.

        if (meta.metadata_tracking.mValid == 0) {
            meta.metadata_tracking.mKeyInTable = meta.metadata_tracking.mKeyCarried;
        } else {
            meta.metadata_tracking.mKeyInTable = meta.metadata_tracking.mKeyInTable;
        }

        if (meta.metadata_tracking.mValid == 0) {
            meta.metadata_tracking.mSwapSpace = 0;
        } else {
            meta.metadata_tracking.mSwapSpace = meta.metadata_tracking.mKeyInTable - meta.metadata_tracking.mKeyCarried;
        }

        // Update hash table.

        if (meta.metadata_tracking.mSwapSpace == 0) {
            tmp_0 = meta.metadata_tracking.mKeyInTable;
        } else if (meta.metadata_tracking.mCountInTable < meta.metadata_tracking.mCountCarried) {
            tmp_0 = meta.metadata_tracking.mKeyCarried;
        } else {
            tmp_0 = meta.metadata_tracking.mKeyInTable;
        }

        level_0_flow_tracker_stage_3_register.write(meta.metadata_tracking.mIndex3, tmp_0);

        if (meta.metadata_tracking.mSwapSpace == 0) {
            tmp_1 = meta.metadata_tracking.mCountInTable + meta.metadata_tracking.mCountCarried;
        } else if (meta.metadata_tracking.mCountInTable < meta.metadata_tracking.mCountCarried) {
            tmp_1 = meta.metadata_tracking.mCountCarried;
        } else {
            tmp_1 = meta.metadata_tracking.mCountInTable;
        }

        level_0_packet_counter_stage_3_register.write(meta.metadata_tracking.mIndex3, tmp_1);        

        if (meta.metadata_tracking.mValid == 0) {
            if (meta.metadata_tracking.mKeyCarried == 0) {
                tmp_2 = 0;
            } else {
                tmp_2 = 1;
            }
        } else {
            tmp_2 = 1;
        }

        level_0_valid_bit_stage_3_register.write(meta.metadata_tracking.mIndex3, tmp_2);

        // Update metadata carried to the next table stage.

        if (meta.metadata_tracking.mSwapSpace == 0) {
            meta.metadata_tracking.mKeyCarried = 0;
        } else {
            meta.metadata_tracking.mKeyCarried = meta.metadata_tracking.mKeyInTable;
        }

        if (meta.metadata_tracking.mSwapSpace == 0) {
            meta.metadata_tracking.mCountCarried = 0;
        } else {
            meta.metadata_tracking.mCountCarried = meta.metadata_tracking.mCountInTable;
        }        
    }                                                          

    action action_level_1_top_k_stage_1() { 

        bit<32> tmp_0;
        bit<32> tmp_1;
        bit<1>  tmp_2;

        // First table stage.
        
        meta.metadata_tracking.mKeyCarried   = meta.metadata_packet.count_register_hash_0;
        meta.metadata_tracking.mCountCarried = 0;
        
        // Read the key and value at that location.
        
        level_1_flow_tracker_stage_1_register.read(tmp_0, meta.metadata_tracking.mIndex1);
        level_1_packet_counter_stage_1_register.read(tmp_1, meta.metadata_tracking.mIndex1);
        level_1_valid_bit_stage_1_register.read(tmp_2, meta.metadata_tracking.mIndex1);       
        
        meta.metadata_tracking.mKeyInTable      = tmp_0;
        meta.metadata_tracking.mCountInTable    = tmp_1;
        meta.metadata_tracking.mValid           = tmp_2;

        // Check if location is empty or has a different key in there.
        
        if (meta.metadata_tracking.mValid == 0) {
            meta.metadata_tracking.mKeyInTable = meta.metadata_tracking.mKeyCarried;
        } else {
            meta.metadata_tracking.mKeyInTable = meta.metadata_tracking.mKeyInTable;
        }

        if (meta.metadata_tracking.mValid == 0) {
            meta.metadata_tracking.mSwapSpace = 0;
        } else {
            meta.metadata_tracking.mSwapSpace = meta.metadata_tracking.mKeyInTable - meta.metadata_tracking.mKeyCarried;    
        }

        // Update hash table.

        level_1_flow_tracker_stage_1_register.write(meta.metadata_tracking.mIndex1, meta.metadata_tracking.mKeyCarried);
        
        if (meta.metadata_tracking.mSwapSpace == 0) {
            tmp_1 = meta.metadata_tracking.mCountInTable + 1;
        } else {
            tmp_1 = 1;
        }
        level_1_packet_counter_stage_1_register.write(meta.metadata_tracking.mIndex1, tmp_1);
        
        level_1_valid_bit_stage_1_register.write(meta.metadata_tracking.mIndex1, 1);

        // Update metadata carried to the next table stage.

        if (meta.metadata_tracking.mSwapSpace == 0) {
            meta.metadata_tracking.mKeyCarried = 0;
        } else {
            meta.metadata_tracking.mKeyCarried = meta.metadata_tracking.mKeyInTable;
        }
        
        if (meta.metadata_tracking.mSwapSpace == 0) {
            meta.metadata_tracking.mCountCarried = 0;
        } else {
            meta.metadata_tracking.mCountCarried = meta.metadata_tracking.mCountInTable;
        }        
    }

    action action_level_1_top_k_stage_2() {

        bit<32> tmp_0;
        bit<32> tmp_1;
        bit<1>  tmp_2;        

        // Read the key and value at that location.

        level_1_flow_tracker_stage_2_register.read(tmp_0, meta.metadata_tracking.mIndex2);
        level_1_packet_counter_stage_2_register.read(tmp_1, meta.metadata_tracking.mIndex2);
        level_1_valid_bit_stage_2_register.read(tmp_2, meta.metadata_tracking.mIndex2);       
        
        meta.metadata_tracking.mKeyInTable      = tmp_0;
        meta.metadata_tracking.mCountInTable    = tmp_1;
        meta.metadata_tracking.mValid           = tmp_2;

        // Check if location is empty or has a different key in there.

        if (meta.metadata_tracking.mValid == 0) {
            meta.metadata_tracking.mKeyInTable = meta.metadata_tracking.mKeyCarried;
        } else {
            meta.metadata_tracking.mKeyInTable = meta.metadata_tracking.mKeyInTable;
        }

        if (meta.metadata_tracking.mValid == 0) {
            meta.metadata_tracking.mSwapSpace = 0;
        } else {
            meta.metadata_tracking.mSwapSpace = meta.metadata_tracking.mKeyInTable - meta.metadata_tracking.mKeyCarried;
        }

        // Update hash table.

        if (meta.metadata_tracking.mSwapSpace == 0) {
            tmp_0 = meta.metadata_tracking.mKeyInTable;
        } else if (meta.metadata_tracking.mCountInTable < meta.metadata_tracking.mCountCarried) {
            tmp_0 = meta.metadata_tracking.mKeyCarried;
        } else {
            tmp_0 = meta.metadata_tracking.mKeyInTable;
        }

        level_1_flow_tracker_stage_2_register.write(meta.metadata_tracking.mIndex2, tmp_0);

        if (meta.metadata_tracking.mSwapSpace == 0) {
            tmp_1 = meta.metadata_tracking.mCountInTable + meta.metadata_tracking.mCountCarried;
        } else if (meta.metadata_tracking.mCountInTable < meta.metadata_tracking.mCountCarried) {
            tmp_1 = meta.metadata_tracking.mCountCarried;
        } else {
            tmp_1 = meta.metadata_tracking.mCountInTable;
        }

        level_1_packet_counter_stage_2_register.write(meta.metadata_tracking.mIndex2, tmp_1);        

        if (meta.metadata_tracking.mValid == 0) {
            if (meta.metadata_tracking.mKeyCarried == 0) {
                tmp_2 = 0;
            } else {
                tmp_2 = 1;
            }
        } else {
            tmp_2 = 1;
        }

        level_1_valid_bit_stage_2_register.write(meta.metadata_tracking.mIndex2, tmp_2);

        // Update metadata carried to the next table stage.

        if (meta.metadata_tracking.mSwapSpace == 0) {
            meta.metadata_tracking.mKeyCarried = 0;
        } else {
            meta.metadata_tracking.mKeyCarried = meta.metadata_tracking.mKeyInTable;
        }

        if (meta.metadata_tracking.mSwapSpace == 0) {
            meta.metadata_tracking.mCountCarried = 0;
        } else {
            meta.metadata_tracking.mCountCarried = meta.metadata_tracking.mCountInTable;
        }        
    }

    action action_level_1_top_k_stage_3() {

        bit<32> tmp_0;
        bit<32> tmp_1;
        bit<1>  tmp_2;        

        // Read the key and value at that location.

        level_1_flow_tracker_stage_3_register.read(tmp_0, meta.metadata_tracking.mIndex3);
        level_1_packet_counter_stage_3_register.read(tmp_1, meta.metadata_tracking.mIndex3);
        level_1_valid_bit_stage_3_register.read(tmp_2, meta.metadata_tracking.mIndex3);       
        
        meta.metadata_tracking.mKeyInTable      = tmp_0;
        meta.metadata_tracking.mCountInTable    = tmp_1;
        meta.metadata_tracking.mValid           = tmp_2;

        // Check if location is empty or has a different key in there.

        if (meta.metadata_tracking.mValid == 0) {
            meta.metadata_tracking.mKeyInTable = meta.metadata_tracking.mKeyCarried;
        } else {
            meta.metadata_tracking.mKeyInTable = meta.metadata_tracking.mKeyInTable;
        }

        if (meta.metadata_tracking.mValid == 0) {
            meta.metadata_tracking.mSwapSpace = 0;
        } else {
            meta.metadata_tracking.mSwapSpace = meta.metadata_tracking.mKeyInTable - meta.metadata_tracking.mKeyCarried;
        }

        // Update hash table.

        if (meta.metadata_tracking.mSwapSpace == 0) {
            tmp_0 = meta.metadata_tracking.mKeyInTable;
        } else if (meta.metadata_tracking.mCountInTable < meta.metadata_tracking.mCountCarried) {
            tmp_0 = meta.metadata_tracking.mKeyCarried;
        } else {
            tmp_0 = meta.metadata_tracking.mKeyInTable;
        }

        level_1_flow_tracker_stage_3_register.write(meta.metadata_tracking.mIndex3, tmp_0);

        if (meta.metadata_tracking.mSwapSpace == 0) {
            tmp_1 = meta.metadata_tracking.mCountInTable + meta.metadata_tracking.mCountCarried;
        } else if (meta.metadata_tracking.mCountInTable < meta.metadata_tracking.mCountCarried) {
            tmp_1 = meta.metadata_tracking.mCountCarried;
        } else {
            tmp_1 = meta.metadata_tracking.mCountInTable;
        }

        level_1_packet_counter_stage_3_register.write(meta.metadata_tracking.mIndex3, tmp_1);        

        if (meta.metadata_tracking.mValid == 0) {
            if (meta.metadata_tracking.mKeyCarried == 0) {
                tmp_2 = 0;
            } else {
                tmp_2 = 1;
            }
        } else {
            tmp_2 = 1;
        }

        level_1_valid_bit_stage_3_register.write(meta.metadata_tracking.mIndex3, tmp_2);

        // Update metadata carried to the next table stage.

        if (meta.metadata_tracking.mSwapSpace == 0) {
            meta.metadata_tracking.mKeyCarried = 0;
        } else {
            meta.metadata_tracking.mKeyCarried = meta.metadata_tracking.mKeyInTable;
        }

        if (meta.metadata_tracking.mSwapSpace == 0) {
            meta.metadata_tracking.mCountCarried = 0;
        } else {
            meta.metadata_tracking.mCountCarried = meta.metadata_tracking.mCountInTable;
        }        
    } 

    action action_level_2_top_k_stage_1() { 

        bit<32> tmp_0;
        bit<32> tmp_1;
        bit<1>  tmp_2;

        // First table stage.
        
        meta.metadata_tracking.mKeyCarried   = meta.metadata_packet.count_register_hash_0;
        meta.metadata_tracking.mCountCarried = 0;
        
        // Read the key and value at that location.
        
        level_2_flow_tracker_stage_1_register.read(tmp_0, meta.metadata_tracking.mIndex1);
        level_2_packet_counter_stage_1_register.read(tmp_1, meta.metadata_tracking.mIndex1);
        level_2_valid_bit_stage_1_register.read(tmp_2, meta.metadata_tracking.mIndex1);       
        
        meta.metadata_tracking.mKeyInTable      = tmp_0;
        meta.metadata_tracking.mCountInTable    = tmp_1;
        meta.metadata_tracking.mValid           = tmp_2;

        // Check if location is empty or has a different key in there.
        
        if (meta.metadata_tracking.mValid == 0) {
            meta.metadata_tracking.mKeyInTable = meta.metadata_tracking.mKeyCarried;
        } else {
            meta.metadata_tracking.mKeyInTable = meta.metadata_tracking.mKeyInTable;
        }

        if (meta.metadata_tracking.mValid == 0) {
            meta.metadata_tracking.mSwapSpace = 0;
        } else {
            meta.metadata_tracking.mSwapSpace = meta.metadata_tracking.mKeyInTable - meta.metadata_tracking.mKeyCarried;    
        }

        // Update hash table.

        level_2_flow_tracker_stage_1_register.write(meta.metadata_tracking.mIndex1, meta.metadata_tracking.mKeyCarried);
        
        if (meta.metadata_tracking.mSwapSpace == 0) {
            tmp_1 = meta.metadata_tracking.mCountInTable + 1;
        } else {
            tmp_1 = 1;
        }
        level_2_packet_counter_stage_1_register.write(meta.metadata_tracking.mIndex1, tmp_1);
        
        level_2_valid_bit_stage_1_register.write(meta.metadata_tracking.mIndex1, 1);

        // Update metadata carried to the next table stage.

        if (meta.metadata_tracking.mSwapSpace == 0) {
            meta.metadata_tracking.mKeyCarried = 0;
        } else {
            meta.metadata_tracking.mKeyCarried = meta.metadata_tracking.mKeyInTable;
        }
        
        if (meta.metadata_tracking.mSwapSpace == 0) {
            meta.metadata_tracking.mCountCarried = 0;
        } else {
            meta.metadata_tracking.mCountCarried = meta.metadata_tracking.mCountInTable;
        }        
    }

    action action_level_2_top_k_stage_2() {

        bit<32> tmp_0;
        bit<32> tmp_1;
        bit<1>  tmp_2;        

        // Read the key and value at that location.

        level_2_flow_tracker_stage_2_register.read(tmp_0, meta.metadata_tracking.mIndex2);
        level_2_packet_counter_stage_2_register.read(tmp_1, meta.metadata_tracking.mIndex2);
        level_2_valid_bit_stage_2_register.read(tmp_2, meta.metadata_tracking.mIndex2);       
        
        meta.metadata_tracking.mKeyInTable      = tmp_0;
        meta.metadata_tracking.mCountInTable    = tmp_1;
        meta.metadata_tracking.mValid           = tmp_2;

        // Check if location is empty or has a different key in there.

        if (meta.metadata_tracking.mValid == 0) {
            meta.metadata_tracking.mKeyInTable = meta.metadata_tracking.mKeyCarried;
        } else {
            meta.metadata_tracking.mKeyInTable = meta.metadata_tracking.mKeyInTable;
        }

        if (meta.metadata_tracking.mValid == 0) {
            meta.metadata_tracking.mSwapSpace = 0;
        } else {
            meta.metadata_tracking.mSwapSpace = meta.metadata_tracking.mKeyInTable - meta.metadata_tracking.mKeyCarried;
        }

        // Update hash table.

        if (meta.metadata_tracking.mSwapSpace == 0) {
            tmp_0 = meta.metadata_tracking.mKeyInTable;
        } else if (meta.metadata_tracking.mCountInTable < meta.metadata_tracking.mCountCarried) {
            tmp_0 = meta.metadata_tracking.mKeyCarried;
        } else {
            tmp_0 = meta.metadata_tracking.mKeyInTable;
        }

        level_2_flow_tracker_stage_2_register.write(meta.metadata_tracking.mIndex2, tmp_0);

        if (meta.metadata_tracking.mSwapSpace == 0) {
            tmp_1 = meta.metadata_tracking.mCountInTable + meta.metadata_tracking.mCountCarried;
        } else if (meta.metadata_tracking.mCountInTable < meta.metadata_tracking.mCountCarried) {
            tmp_1 = meta.metadata_tracking.mCountCarried;
        } else {
            tmp_1 = meta.metadata_tracking.mCountInTable;
        }

        level_2_packet_counter_stage_2_register.write(meta.metadata_tracking.mIndex2, tmp_1);        

        if (meta.metadata_tracking.mValid == 0) {
            if (meta.metadata_tracking.mKeyCarried == 0) {
                tmp_2 = 0;
            } else {
                tmp_2 = 1;
            }
        } else {
            tmp_2 = 1;
        }

        level_2_valid_bit_stage_2_register.write(meta.metadata_tracking.mIndex2, tmp_2);

        // Update metadata carried to the next table stage.

        if (meta.metadata_tracking.mSwapSpace == 0) {
            meta.metadata_tracking.mKeyCarried = 0;
        } else {
            meta.metadata_tracking.mKeyCarried = meta.metadata_tracking.mKeyInTable;
        }

        if (meta.metadata_tracking.mSwapSpace == 0) {
            meta.metadata_tracking.mCountCarried = 0;
        } else {
            meta.metadata_tracking.mCountCarried = meta.metadata_tracking.mCountInTable;
        }        
    }

    action action_level_2_top_k_stage_3() {

        bit<32> tmp_0;
        bit<32> tmp_1;
        bit<1>  tmp_2;        

        // Read the key and value at that location.

        level_2_flow_tracker_stage_3_register.read(tmp_0, meta.metadata_tracking.mIndex3);
        level_2_packet_counter_stage_3_register.read(tmp_1, meta.metadata_tracking.mIndex3);
        level_2_valid_bit_stage_3_register.read(tmp_2, meta.metadata_tracking.mIndex3);       
        
        meta.metadata_tracking.mKeyInTable      = tmp_0;
        meta.metadata_tracking.mCountInTable    = tmp_1;
        meta.metadata_tracking.mValid           = tmp_2;

        // Check if location is empty or has a different key in there.

        if (meta.metadata_tracking.mValid == 0) {
            meta.metadata_tracking.mKeyInTable = meta.metadata_tracking.mKeyCarried;
        } else {
            meta.metadata_tracking.mKeyInTable = meta.metadata_tracking.mKeyInTable;
        }

        if (meta.metadata_tracking.mValid == 0) {
            meta.metadata_tracking.mSwapSpace = 0;
        } else {
            meta.metadata_tracking.mSwapSpace = meta.metadata_tracking.mKeyInTable - meta.metadata_tracking.mKeyCarried;
        }

        // Update hash table.

        if (meta.metadata_tracking.mSwapSpace == 0) {
            tmp_0 = meta.metadata_tracking.mKeyInTable;
        } else if (meta.metadata_tracking.mCountInTable < meta.metadata_tracking.mCountCarried) {
            tmp_0 = meta.metadata_tracking.mKeyCarried;
        } else {
            tmp_0 = meta.metadata_tracking.mKeyInTable;
        }

        level_2_flow_tracker_stage_3_register.write(meta.metadata_tracking.mIndex3, tmp_0);

        if (meta.metadata_tracking.mSwapSpace == 0) {
            tmp_1 = meta.metadata_tracking.mCountInTable + meta.metadata_tracking.mCountCarried;
        } else if (meta.metadata_tracking.mCountInTable < meta.metadata_tracking.mCountCarried) {
            tmp_1 = meta.metadata_tracking.mCountCarried;
        } else {
            tmp_1 = meta.metadata_tracking.mCountInTable;
        }

        level_2_packet_counter_stage_3_register.write(meta.metadata_tracking.mIndex3, tmp_1);        

        if (meta.metadata_tracking.mValid == 0) {
            if (meta.metadata_tracking.mKeyCarried == 0) {
                tmp_2 = 0;
            } else {
                tmp_2 = 1;
            }
        } else {
            tmp_2 = 1;
        }

        level_2_valid_bit_stage_3_register.write(meta.metadata_tracking.mIndex3, tmp_2);

        // Update metadata carried to the next table stage.

        if (meta.metadata_tracking.mSwapSpace == 0) {
            meta.metadata_tracking.mKeyCarried = 0;
        } else {
            meta.metadata_tracking.mKeyCarried = meta.metadata_tracking.mKeyInTable;
        }

        if (meta.metadata_tracking.mSwapSpace == 0) {
            meta.metadata_tracking.mCountCarried = 0;
        } else {
            meta.metadata_tracking.mCountCarried = meta.metadata_tracking.mCountInTable;
        }        
    } 

    action action_level_3_top_k_stage_1() { 

        bit<32> tmp_0;
        bit<32> tmp_1;
        bit<1>  tmp_2;

        // First table stage.
        
        meta.metadata_tracking.mKeyCarried   = meta.metadata_packet.count_register_hash_0;
        meta.metadata_tracking.mCountCarried = 0;
        
        // Read the key and value at that location.
        
        level_3_flow_tracker_stage_1_register.read(tmp_0, meta.metadata_tracking.mIndex1);
        level_3_packet_counter_stage_1_register.read(tmp_1, meta.metadata_tracking.mIndex1);
        level_3_valid_bit_stage_1_register.read(tmp_2, meta.metadata_tracking.mIndex1);       
        
        meta.metadata_tracking.mKeyInTable      = tmp_0;
        meta.metadata_tracking.mCountInTable    = tmp_1;
        meta.metadata_tracking.mValid           = tmp_2;

        // Check if location is empty or has a different key in there.
        
        if (meta.metadata_tracking.mValid == 0) {
            meta.metadata_tracking.mKeyInTable = meta.metadata_tracking.mKeyCarried;
        } else {
            meta.metadata_tracking.mKeyInTable = meta.metadata_tracking.mKeyInTable;
        }

        if (meta.metadata_tracking.mValid == 0) {
            meta.metadata_tracking.mSwapSpace = 0;
        } else {
            meta.metadata_tracking.mSwapSpace = meta.metadata_tracking.mKeyInTable - meta.metadata_tracking.mKeyCarried;    
        }

        // Update hash table.

        level_3_flow_tracker_stage_1_register.write(meta.metadata_tracking.mIndex1, meta.metadata_tracking.mKeyCarried);
        
        if (meta.metadata_tracking.mSwapSpace == 0) {
            tmp_1 = meta.metadata_tracking.mCountInTable + 1;
        } else {
            tmp_1 = 1;
        }
        level_3_packet_counter_stage_1_register.write(meta.metadata_tracking.mIndex1, tmp_1);
        
        level_3_valid_bit_stage_1_register.write(meta.metadata_tracking.mIndex1, 1);

        // Update metadata carried to the next table stage.

        if (meta.metadata_tracking.mSwapSpace == 0) {
            meta.metadata_tracking.mKeyCarried = 0;
        } else {
            meta.metadata_tracking.mKeyCarried = meta.metadata_tracking.mKeyInTable;
        }
        
        if (meta.metadata_tracking.mSwapSpace == 0) {
            meta.metadata_tracking.mCountCarried = 0;
        } else {
            meta.metadata_tracking.mCountCarried = meta.metadata_tracking.mCountInTable;
        }        
    }

    action action_level_3_top_k_stage_2() {

        bit<32> tmp_0;
        bit<32> tmp_1;
        bit<1>  tmp_2;        

        // Read the key and value at that location.

        level_3_flow_tracker_stage_2_register.read(tmp_0, meta.metadata_tracking.mIndex2);
        level_3_packet_counter_stage_2_register.read(tmp_1, meta.metadata_tracking.mIndex2);
        level_3_valid_bit_stage_2_register.read(tmp_2, meta.metadata_tracking.mIndex2);       
        
        meta.metadata_tracking.mKeyInTable      = tmp_0;
        meta.metadata_tracking.mCountInTable    = tmp_1;
        meta.metadata_tracking.mValid           = tmp_2;

        // Check if location is empty or has a different key in there.

        if (meta.metadata_tracking.mValid == 0) {
            meta.metadata_tracking.mKeyInTable = meta.metadata_tracking.mKeyCarried;
        } else {
            meta.metadata_tracking.mKeyInTable = meta.metadata_tracking.mKeyInTable;
        }

        if (meta.metadata_tracking.mValid == 0) {
            meta.metadata_tracking.mSwapSpace = 0;
        } else {
            meta.metadata_tracking.mSwapSpace = meta.metadata_tracking.mKeyInTable - meta.metadata_tracking.mKeyCarried;
        }

        // Update hash table.

        if (meta.metadata_tracking.mSwapSpace == 0) {
            tmp_0 = meta.metadata_tracking.mKeyInTable;
        } else if (meta.metadata_tracking.mCountInTable < meta.metadata_tracking.mCountCarried) {
            tmp_0 = meta.metadata_tracking.mKeyCarried;
        } else {
            tmp_0 = meta.metadata_tracking.mKeyInTable;
        }

        level_3_flow_tracker_stage_2_register.write(meta.metadata_tracking.mIndex2, tmp_0);

        if (meta.metadata_tracking.mSwapSpace == 0) {
            tmp_1 = meta.metadata_tracking.mCountInTable + meta.metadata_tracking.mCountCarried;
        } else if (meta.metadata_tracking.mCountInTable < meta.metadata_tracking.mCountCarried) {
            tmp_1 = meta.metadata_tracking.mCountCarried;
        } else {
            tmp_1 = meta.metadata_tracking.mCountInTable;
        }

        level_3_packet_counter_stage_2_register.write(meta.metadata_tracking.mIndex2, tmp_1);        

        if (meta.metadata_tracking.mValid == 0) {
            if (meta.metadata_tracking.mKeyCarried == 0) {
                tmp_2 = 0;
            } else {
                tmp_2 = 1;
            }
        } else {
            tmp_2 = 1;
        }

        level_3_valid_bit_stage_2_register.write(meta.metadata_tracking.mIndex2, tmp_2);

        // Update metadata carried to the next table stage.

        if (meta.metadata_tracking.mSwapSpace == 0) {
            meta.metadata_tracking.mKeyCarried = 0;
        } else {
            meta.metadata_tracking.mKeyCarried = meta.metadata_tracking.mKeyInTable;
        }

        if (meta.metadata_tracking.mSwapSpace == 0) {
            meta.metadata_tracking.mCountCarried = 0;
        } else {
            meta.metadata_tracking.mCountCarried = meta.metadata_tracking.mCountInTable;
        }        
    }

    action action_level_3_top_k_stage_3() {

        bit<32> tmp_0;
        bit<32> tmp_1;
        bit<1>  tmp_2;        

        // Read the key and value at that location.

        level_3_flow_tracker_stage_3_register.read(tmp_0, meta.metadata_tracking.mIndex3);
        level_3_packet_counter_stage_3_register.read(tmp_1, meta.metadata_tracking.mIndex3);
        level_3_valid_bit_stage_3_register.read(tmp_2, meta.metadata_tracking.mIndex3);       
        
        meta.metadata_tracking.mKeyInTable      = tmp_0;
        meta.metadata_tracking.mCountInTable    = tmp_1;
        meta.metadata_tracking.mValid           = tmp_2;

        // Check if location is empty or has a different key in there.

        if (meta.metadata_tracking.mValid == 0) {
            meta.metadata_tracking.mKeyInTable = meta.metadata_tracking.mKeyCarried;
        } else {
            meta.metadata_tracking.mKeyInTable = meta.metadata_tracking.mKeyInTable;
        }

        if (meta.metadata_tracking.mValid == 0) {
            meta.metadata_tracking.mSwapSpace = 0;
        } else {
            meta.metadata_tracking.mSwapSpace = meta.metadata_tracking.mKeyInTable - meta.metadata_tracking.mKeyCarried;
        }

        // Update hash table.

        if (meta.metadata_tracking.mSwapSpace == 0) {
            tmp_0 = meta.metadata_tracking.mKeyInTable;
        } else if (meta.metadata_tracking.mCountInTable < meta.metadata_tracking.mCountCarried) {
            tmp_0 = meta.metadata_tracking.mKeyCarried;
        } else {
            tmp_0 = meta.metadata_tracking.mKeyInTable;
        }

        level_3_flow_tracker_stage_3_register.write(meta.metadata_tracking.mIndex3, tmp_0);

        if (meta.metadata_tracking.mSwapSpace == 0) {
            tmp_1 = meta.metadata_tracking.mCountInTable + meta.metadata_tracking.mCountCarried;
        } else if (meta.metadata_tracking.mCountInTable < meta.metadata_tracking.mCountCarried) {
            tmp_1 = meta.metadata_tracking.mCountCarried;
        } else {
            tmp_1 = meta.metadata_tracking.mCountInTable;
        }

        level_3_packet_counter_stage_3_register.write(meta.metadata_tracking.mIndex3, tmp_1);        

        if (meta.metadata_tracking.mValid == 0) {
            if (meta.metadata_tracking.mKeyCarried == 0) {
                tmp_2 = 0;
            } else {
                tmp_2 = 1;
            }
        } else {
            tmp_2 = 1;
        }

        level_3_valid_bit_stage_3_register.write(meta.metadata_tracking.mIndex3, tmp_2);

        // Update metadata carried to the next table stage.

        if (meta.metadata_tracking.mSwapSpace == 0) {
            meta.metadata_tracking.mKeyCarried = 0;
        } else {
            meta.metadata_tracking.mKeyCarried = meta.metadata_tracking.mKeyInTable;
        }

        if (meta.metadata_tracking.mSwapSpace == 0) {
            meta.metadata_tracking.mCountCarried = 0;
        } else {
            meta.metadata_tracking.mCountCarried = meta.metadata_tracking.mCountInTable;
        }        
    } 

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

                if ((hdr.ipv4.src_addr == (bit<32>)167772161) ||
                    (hdr.ipv4.src_addr == (bit<32>)167772162)) {
                    return;
                }

                // Calculate the count sketch register hashes.
                action_count_register_hash_0();
                action_count_register_hash_1();
                action_count_register_hash_2();
                action_count_register_hash_3();

                // Check if the current packet is part of a pingall.

                if (meta.metadata_packet.count_register_hash_0 == (bit<32>)116335) {
                    return;
                }                

                // Calculate the count sketch update hashes.
                action_count_update_hash_0();
                action_count_update_hash_1();
                action_count_update_hash_2();
                action_count_update_hash_3();

                // Calculate the hash values for the 3 top-k stages.
                action_top_k_stage_1_hash();
                action_top_k_stage_2_hash();
                action_top_k_stage_3_hash();

                // Sketching Level 0
                action_level_0_count_sketch_incr();

                // Top-k Level 0
                action_level_0_top_k_stage_1();
                action_level_0_top_k_stage_2();
                action_level_0_top_k_stage_3();

                // Sampling Level 1
                action_binary_hash_1();
                if (meta.metadata_packet.binary_hash_1 == 0) {
                    return;
                }

                // Sketching Level 1
                action_level_1_count_sketch_incr();              

                // Top-k Level 1
                action_level_1_top_k_stage_1();
                action_level_1_top_k_stage_2();
                action_level_1_top_k_stage_3();                

                // Sampling Level 2
                action_binary_hash_2();
                if (meta.metadata_packet.binary_hash_2 == 0) {
                    return;
                }

                // Sketching Level 2
                action_level_2_count_sketch_incr();             

                // Top-k Level 2
                action_level_2_top_k_stage_1();
                action_level_2_top_k_stage_2();
                action_level_2_top_k_stage_3();                

                // Sampling Level 3
                action_binary_hash_3();
                if (meta.metadata_packet.binary_hash_3 == 0) {
                    return;
                }

                // Sketching Level 3
                action_level_3_count_sketch_incr();            

                // Top-k Level 3
                action_level_3_top_k_stage_1();
                action_level_3_top_k_stage_2();
                action_level_3_top_k_stage_3();

                return;                
            }
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