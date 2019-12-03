control c_cmSketch(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

    register<bit<32>>(REG_SKETCH_SIZE)  cm_ip_0_register;
    register<bit<32>>(REG_SKETCH_SIZE)  cm_ip_1_register;  
    register<bit<32>>(REG_SKETCH_SIZE)  cm_ip_2_register;  
    register<bit<32>>(REG_SKETCH_SIZE)  cm_ip_final_register;

    register<bit<32>>(REG_SKETCH_SIZE)  cm_5t_0_register;
    register<bit<32>>(REG_SKETCH_SIZE)  cm_5t_1_register;  
    register<bit<32>>(REG_SKETCH_SIZE)  cm_5t_2_register;  
    register<bit<32>>(REG_SKETCH_SIZE)  cm_5t_final_register;    

    action cm_ip_0_hash() {
        hash(meta.cm_meta.cm_ip_0_hash, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr}, 
            (bit<32>)REG_SKETCH_SIZE);
    }

    action cm_ip_1_hash() {
        hash(meta.cm_meta.cm_ip_1_hash, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr}, 
            (bit<32>)REG_SKETCH_SIZE);
    }

    action cm_ip_2_hash() {
        hash(meta.cm_meta.cm_ip_2_hash, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr},
            (bit<32>)REG_SKETCH_SIZE);
    }

    action cm_5t_0_hash() {
        hash(meta.cm_meta.cm_5t_0_hash, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.meta.l4_src_port, (bit<32>)meta.meta.l4_dst_port}, 
            (bit<32>)REG_SKETCH_SIZE);
    }

    action cm_5t_1_hash() {
        hash(meta.cm_meta.cm_5t_1_hash, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.meta.l4_src_port, (bit<32>)meta.meta.l4_dst_port}, 
            (bit<32>)REG_SKETCH_SIZE);
    }

    action cm_5t_2_hash() {
        hash(meta.cm_meta.cm_5t_2_hash, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.meta.l4_src_port, (bit<32>)meta.meta.l4_dst_port}, 
            (bit<32>)REG_SKETCH_SIZE);
    }                 

    action cm_incr() {

        cm_ip_0_register.read(meta.cm_meta.cm_ip_0_sketch, (bit<32>)meta.cm_meta.cm_ip_0_hash);
        cm_ip_1_register.read(meta.cm_meta.cm_ip_1_sketch, (bit<32>)meta.cm_meta.cm_ip_1_hash);
        cm_ip_2_register.read(meta.cm_meta.cm_ip_2_sketch, (bit<32>)meta.cm_meta.cm_ip_2_hash);

        cm_5t_0_register.read(meta.cm_meta.cm_5t_0_sketch, (bit<32>)meta.cm_meta.cm_5t_0_hash);
        cm_5t_1_register.read(meta.cm_meta.cm_5t_1_sketch, (bit<32>)meta.cm_meta.cm_5t_1_hash);
        cm_5t_2_register.read(meta.cm_meta.cm_5t_2_sketch, (bit<32>)meta.cm_meta.cm_5t_2_hash);        

        // Increment is made using the metadata, instead of directly on the registers.
        // This allows us to perform the final value comparison on the apply{} block.
        
        meta.cm_meta.cm_ip_0_sketch = meta.cm_meta.cm_ip_0_sketch + 1;
        meta.cm_meta.cm_ip_1_sketch = meta.cm_meta.cm_ip_1_sketch + 1;
        meta.cm_meta.cm_ip_2_sketch = meta.cm_meta.cm_ip_2_sketch + 1;

        meta.cm_meta.cm_5t_0_sketch = meta.cm_meta.cm_5t_0_sketch + 1;
        meta.cm_meta.cm_5t_1_sketch = meta.cm_meta.cm_5t_1_sketch + 1;
        meta.cm_meta.cm_5t_2_sketch = meta.cm_meta.cm_5t_2_sketch + 1;        

        cm_ip_0_register.write((bit<32>)meta.cm_meta.cm_ip_0_hash, meta.cm_meta.cm_ip_0_sketch);
        cm_ip_1_register.write((bit<32>)meta.cm_meta.cm_ip_1_hash, meta.cm_meta.cm_ip_1_sketch);
        cm_ip_2_register.write((bit<32>)meta.cm_meta.cm_ip_2_hash, meta.cm_meta.cm_ip_2_sketch);

        cm_5t_0_register.write((bit<32>)meta.cm_meta.cm_5t_0_hash, meta.cm_meta.cm_5t_0_sketch);
        cm_5t_1_register.write((bit<32>)meta.cm_meta.cm_5t_1_hash, meta.cm_meta.cm_5t_1_sketch);
        cm_5t_2_register.write((bit<32>)meta.cm_meta.cm_5t_2_hash, meta.cm_meta.cm_5t_2_sketch);        
    }

    action cm_register_write() {
        cm_ip_final_register.write((bit<32>)meta.cm_meta.cm_ip_2_hash, meta.cm_meta.cm_ip_final_sketch);
        cm_5t_final_register.write((bit<32>)meta.cm_meta.cm_5t_2_hash, meta.cm_meta.cm_5t_final_sketch);
    }

	apply {
		
       // Count-min sketch.
       cm_ip_0_hash();
       cm_ip_1_hash();
       cm_ip_2_hash();

       cm_5t_0_hash();
       cm_5t_1_hash();
       cm_5t_2_hash();       
       
       // Increment the value on all registers.
       cm_incr();

       // Compare the current value on all registers and identify the smallest.
       meta.cm_meta.cm_ip_final_sketch = meta.cm_meta.cm_ip_0_sketch;
       meta.cm_meta.cm_5t_final_sketch = meta.cm_meta.cm_5t_0_sketch;

       if (meta.cm_meta.cm_ip_final_sketch > meta.cm_meta.cm_ip_1_sketch) {
           meta.cm_meta.cm_ip_final_sketch = meta.cm_meta.cm_ip_1_sketch;
       }
       
       if (meta.cm_meta.cm_ip_final_sketch > meta.cm_meta.cm_ip_2_sketch) {
           meta.cm_meta.cm_ip_final_sketch = meta.cm_meta.cm_ip_2_sketch;
       }

       if (meta.cm_meta.cm_5t_final_sketch > meta.cm_meta.cm_5t_1_sketch) {
           meta.cm_meta.cm_5t_final_sketch = meta.cm_meta.cm_5t_1_sketch;
       }
       
       if (meta.cm_meta.cm_5t_final_sketch > meta.cm_meta.cm_5t_2_sketch) {
           meta.cm_meta.cm_5t_final_sketch = meta.cm_meta.cm_5t_2_sketch;
       }       

       // Write the smallest value to the final count-min register.
       cm_register_write();
	}	

}
