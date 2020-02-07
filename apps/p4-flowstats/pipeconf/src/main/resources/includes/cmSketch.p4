control c_cmSketch(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

    register<bit<32>>(REG_SKETCH_SIZE)  register_ip_0;
    register<bit<32>>(REG_SKETCH_SIZE)  register_ip_1;  
    register<bit<32>>(REG_SKETCH_SIZE)  register_ip_2;  
    register<bit<32>>(REG_SKETCH_SIZE)  register_ip_final;

    register<bit<32>>(REG_SKETCH_SIZE)  register_5t_0;
    register<bit<32>>(REG_SKETCH_SIZE)  register_5t_1;  
    register<bit<32>>(REG_SKETCH_SIZE)  register_5t_2;  
    register<bit<32>>(REG_SKETCH_SIZE)  register_5t_final;    

    action hash_ip_0() {
        hash(meta.cm.hash_ip_0, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr}, 
            (bit<32>)REG_SKETCH_SIZE);
    }

    action hash_ip_1() {
        hash(meta.cm.hash_ip_1, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr}, 
            (bit<32>)REG_SKETCH_SIZE);
    }

    action hash_ip_2() {
        hash(meta.cm.hash_ip_2, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr},
            (bit<32>)REG_SKETCH_SIZE);
    }

    action hash_5t_0() {
        hash(meta.cm.hash_5t_0, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.meta.l4_src_port, (bit<32>)meta.meta.l4_dst_port}, 
            (bit<32>)REG_SKETCH_SIZE);
    }

    action hash_5t_1() {
        hash(meta.cm.hash_5t_1, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.meta.l4_src_port, (bit<32>)meta.meta.l4_dst_port}, 
            (bit<32>)REG_SKETCH_SIZE);
    }

    action hash_5t_2() {
        hash(meta.cm.hash_5t_2, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.meta.l4_src_port, (bit<32>)meta.meta.l4_dst_port}, 
            (bit<32>)REG_SKETCH_SIZE);
    }                 

    action cm_incr() {

        register_ip_0.read(meta.cm.sketch_ip_0, (bit<32>)meta.cm.hash_ip_0);
        register_ip_1.read(meta.cm.sketch_ip_1, (bit<32>)meta.cm.hash_ip_1);
        register_ip_2.read(meta.cm.sketch_ip_2, (bit<32>)meta.cm.hash_ip_2);

        register_5t_0.read(meta.cm.sketch_5t_0, (bit<32>)meta.cm.hash_5t_0);
        register_5t_1.read(meta.cm.sketch_5t_1, (bit<32>)meta.cm.hash_5t_1);
        register_5t_2.read(meta.cm.sketch_5t_2, (bit<32>)meta.cm.hash_5t_2);        

        // Increment is made using the metadata, instead of directly on the registers.
        // This allows us to perform the final value comparison on the apply{} block.
        
        meta.cm.sketch_ip_0 = meta.cm.sketch_ip_0 + 1;
        meta.cm.sketch_ip_1 = meta.cm.sketch_ip_1 + 1;
        meta.cm.sketch_ip_2 = meta.cm.sketch_ip_2 + 1;

        meta.cm.sketch_5t_0 = meta.cm.sketch_5t_0 + 1;
        meta.cm.sketch_5t_1 = meta.cm.sketch_5t_1 + 1;
        meta.cm.sketch_5t_2 = meta.cm.sketch_5t_2 + 1;        

        register_ip_0.write((bit<32>)meta.cm.hash_ip_0, meta.cm.sketch_ip_0);
        register_ip_1.write((bit<32>)meta.cm.hash_ip_1, meta.cm.sketch_ip_1);
        register_ip_2.write((bit<32>)meta.cm.hash_ip_2, meta.cm.sketch_ip_2);

        register_5t_0.write((bit<32>)meta.cm.hash_5t_0, meta.cm.sketch_5t_0);
        register_5t_1.write((bit<32>)meta.cm.hash_5t_1, meta.cm.sketch_5t_1);
        register_5t_2.write((bit<32>)meta.cm.hash_5t_2, meta.cm.sketch_5t_2);        
    }

    action cm_register_write() {
        register_ip_final.write((bit<32>)meta.cm.hash_ip_2, meta.cm.sketch_ip_final);
        register_5t_final.write((bit<32>)meta.cm.hash_5t_2, meta.cm.sketch_5t_final);
    }

	apply {
		
       // Count-min sketch.
       hash_ip_0();
       hash_ip_1();
       hash_ip_2();

       hash_5t_0();
       hash_5t_1();
       hash_5t_2();       
       
       // Increment the value on all registers.
       cm_incr();

       // Compare the current value on all registers and identify the smallest.
       meta.cm.sketch_ip_final = meta.cm.sketch_ip_0;
       meta.cm.sketch_5t_final = meta.cm.sketch_5t_0;

       if (meta.cm.sketch_ip_final > meta.cm.sketch_ip_1) {
           meta.cm.sketch_ip_final = meta.cm.sketch_ip_1;
       }
       
       if (meta.cm.sketch_ip_final > meta.cm.sketch_ip_2) {
           meta.cm.sketch_ip_final = meta.cm.sketch_ip_2;
       }

       if (meta.cm.sketch_5t_final > meta.cm.sketch_5t_1) {
           meta.cm.sketch_5t_final = meta.cm.sketch_5t_1;
       }
       
       if (meta.cm.sketch_5t_final > meta.cm.sketch_5t_2) {
           meta.cm.sketch_5t_final = meta.cm.sketch_5t_2;
       }       

       // Write the smallest value to the final count-min register.
       cm_register_write();
	}	

}
