control c_amsSketch(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

    register<bit<32>>(REG_SKETCH_SIZE)  register_0;
    register<bit<32>>(REG_SKETCH_SIZE)  register_1;  
    register<bit<32>>(REG_SKETCH_SIZE)  register_2;
    register<bit<32>>(REG_SKETCH_SIZE)  register_3;
    register<bit<32>>(4)                register_sum;   
    register<bit<32>>(REG_SKETCH_SIZE)  register_final;

    action hash_0() {
        hash(meta.ams.hash_0, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr}, 
            (bit<32>)REG_SKETCH_SIZE);
    }

    action hash_1() {
        hash(meta.ams.hash_1, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr}, 
            (bit<32>)REG_SKETCH_SIZE);
    }

    action hash_2() {
        hash(meta.ams.hash_2, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr},
            (bit<32>)REG_SKETCH_SIZE);
    }

    action hash_3() {
        hash(meta.ams.hash_3, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr},
            (bit<32>)REG_SKETCH_SIZE);
    }    

    // Second hash function that returns 0 or 1, corresponding to {-1, +1} from the original sketch.
    // These will be multiplied with the values to be added in the target counter.

    action hash_g_0() {
        hash(meta.ams.hash_g_0, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr},
            (bit<32>)2);        
    }

    action hash_g_1() {
        hash(meta.ams.hash_g_1, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr},
            (bit<32>)2);        
    }

    action hash_g_2() {
        hash(meta.ams.hash_g_2, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr},
            (bit<32>)2);        
    } 

    action hash_g_3() {
        hash(meta.ams.hash_g_3, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr},
            (bit<32>)2);        
    }           

    action ams_update() {

        register_0.read(meta.ams.sketch_0, (bit<32>)meta.ams.hash_0);
        register_1.read(meta.ams.sketch_1, (bit<32>)meta.ams.hash_1);
        register_2.read(meta.ams.sketch_2, (bit<32>)meta.ams.hash_2);
        register_3.read(meta.ams.sketch_3, (bit<32>)meta.ams.hash_3);

        register_sum.read(meta.ams.sum_0, (bit<32>)0);
        register_sum.read(meta.ams.sum_1, (bit<32>)1);
        register_sum.read(meta.ams.sum_2, (bit<32>)2);
        register_sum.read(meta.ams.sum_3, (bit<32>)3);

        // The update is made using the metadata, instead of directly on the registers.
        // We also update the current sum value (removing the old sketch value from it first).

        if (meta.ams.hash_g_0 == 0) {
            meta.ams.sketch_0 = meta.ams.sketch_0 - 1;
            meta.ams.sum_0    = meta.ams.sum_0 - ((meta.ams.sketch_0 + 1) * (meta.ams.sketch_0 + 1))
                                               + ((meta.ams.sketch_0) * (meta.ams.sketch_0));                      
        } else {
            meta.ams.sketch_0 = meta.ams.sketch_0 + 1;
            meta.ams.sum_0    = meta.ams.sum_0 - ((meta.ams.sketch_0 - 1) * (meta.ams.sketch_0 - 1))
                                               + ((meta.ams.sketch_0) * (meta.ams.sketch_0));            
        }

        if (meta.ams.hash_g_1 == 0) {
            meta.ams.sketch_1 = meta.ams.sketch_1 - 1;
            meta.ams.sum_1    = meta.ams.sum_1 - ((meta.ams.sketch_1 + 1) * (meta.ams.sketch_1 + 1))
                                               + ((meta.ams.sketch_1) * (meta.ams.sketch_1));                      
        } else {
            meta.ams.sketch_1 = meta.ams.sketch_1 + 1;
            meta.ams.sum_1    = meta.ams.sum_1 - ((meta.ams.sketch_1 - 1) * (meta.ams.sketch_1 - 1))
                                               + ((meta.ams.sketch_1) * (meta.ams.sketch_1));            
        } 

        if (meta.ams.hash_g_2 == 0) {
            meta.ams.sketch_2 = meta.ams.sketch_2 - 1;
            meta.ams.sum_2    = meta.ams.sum_2 - ((meta.ams.sketch_2 + 1) * (meta.ams.sketch_2 + 1))
                                               + ((meta.ams.sketch_2) * (meta.ams.sketch_2));                      
        } else {
            meta.ams.sketch_2 = meta.ams.sketch_2 + 1;
            meta.ams.sum_2    = meta.ams.sum_2 - ((meta.ams.sketch_2 - 1) * (meta.ams.sketch_2 - 1))
                                               + ((meta.ams.sketch_2) * (meta.ams.sketch_2));            
        } 

        if (meta.ams.hash_g_3 == 0) {
            meta.ams.sketch_3 = meta.ams.sketch_3 - 1;
            meta.ams.sum_3    = meta.ams.sum_3 - ((meta.ams.sketch_3 + 1) * (meta.ams.sketch_3 + 1))
                                               + ((meta.ams.sketch_3) * (meta.ams.sketch_3));                      
        } else {
            meta.ams.sketch_3 = meta.ams.sketch_3 + 1;
            meta.ams.sum_3    = meta.ams.sum_3 - ((meta.ams.sketch_3 - 1) * (meta.ams.sketch_3 - 1))
                                               + ((meta.ams.sketch_3) * (meta.ams.sketch_3));            
        }                                         

        register_0.write((bit<32>)meta.ams.hash_0, meta.ams.sketch_0);
        register_1.write((bit<32>)meta.ams.hash_1, meta.ams.sketch_1);
        register_2.write((bit<32>)meta.ams.hash_2, meta.ams.sketch_2); 
        register_3.write((bit<32>)meta.ams.hash_3, meta.ams.sketch_3);

        register_sum.write((bit<32>)0, meta.ams.sum_0);
        register_sum.write((bit<32>)1, meta.ams.sum_1);
        register_sum.write((bit<32>)2, meta.ams.sum_2);
        register_sum.write((bit<32>)3, meta.ams.sum_3);             
    }

    action ams_register_write() {
        register_final.write((bit<32>)meta.ams.hash_3, meta.ams.sketch_final);
    }

    action ams_median(bit<32> aux_0, bit<32> aux_1, bit<32> aux_2, bit<32> aux_3) {

        if  ((aux_0 <= aux_1 && aux_0 <= aux_2 && aux_0 >= aux_3) ||
             (aux_0 <= aux_1 && aux_0 <= aux_3 && aux_0 >= aux_2) ||
             (aux_0 <= aux_1 && aux_0 >= aux_2 && aux_0 >= aux_3) ||
             (aux_0 <= aux_2 && aux_0 <= aux_3 && aux_0 >= aux_1) ||
             (aux_0 <= aux_2 && aux_0 >= aux_1 && aux_0 >= aux_3) ||
             (aux_0 <= aux_3 && aux_0 >= aux_1 && aux_0 >= aux_2)) {
                meta.ams.sketch_final = aux_0;
        } 
        else if ((aux_1 <= aux_0 && aux_1 <= aux_2 && aux_1 >= aux_3) ||
                 (aux_1 <= aux_0 && aux_1 <= aux_3 && aux_1 >= aux_2) ||
                 (aux_1 <= aux_0 && aux_1 >= aux_2 && aux_1 >= aux_3) ||
                 (aux_1 <= aux_2 && aux_1 <= aux_3 && aux_1 >= aux_0) ||
                 (aux_1 <= aux_2 && aux_1 >= aux_0 && aux_1 >= aux_3) ||
                 (aux_1 <= aux_3 && aux_1 >= aux_0 && aux_1 >= aux_2)) {
                    meta.ams.sketch_final = aux_1;
        }
        else if ((aux_2 <= aux_1 && aux_2 <= aux_0 && aux_2 >= aux_3) ||
                 (aux_2 <= aux_1 && aux_2 <= aux_3 && aux_2 >= aux_0) ||
                 (aux_2 <= aux_1 && aux_2 >= aux_0 && aux_2 >= aux_3) ||
                 (aux_2 <= aux_0 && aux_2 <= aux_3 && aux_2 >= aux_1) ||
                 (aux_2 <= aux_0 && aux_2 >= aux_1 && aux_2 >= aux_3) ||
                 (aux_2 <= aux_3 && aux_2 >= aux_1 && aux_2 >= aux_0)) {
                    meta.ams.sketch_final = aux_2;
        }
        else {
            meta.ams.sketch_final = aux_3;
        }        
    }

    apply {
        
        // AMS sketch.
        
        hash_0();
        hash_1();
        hash_2();
        hash_3();
        hash_g_0();
        hash_g_1();
        hash_g_2();
        hash_g_3();
       
        // Increment or decrement the value on all registers.
        ams_update();

        // Obtain the median value from all registers.
        ams_median(meta.ams.sum_0, 
                   meta.ams.sum_1,
                   meta.ams.sum_2,
                   meta.ams.sum_3);

        ams_register_write();        
    }   

}
