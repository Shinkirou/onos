control c_cmSketch(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

    register<bit<32>>(REG_SKETCH_SIZE)  cm_0_register;
    register<bit<32>>(REG_SKETCH_SIZE)  cm_1_register;  
    register<bit<32>>(REG_SKETCH_SIZE)  cm_2_register;  
    register<bit<32>>(REG_SKETCH_SIZE)  cm_final_register;

    //bit<32> cm_0_hash;
    //bit<32> cm_1_hash;
    //bit<32> cm_2_hash;

    action cm_0_hash() {
        hash(meta.cm_meta.cm_0_hash, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr}, 
            (bit<32>)REG_SKETCH_SIZE);
        //meta.cm_meta.cm_0_hash = cm_0_hash;
    }

    action cm_1_hash() {
        hash(meta.cm_meta.cm_1_hash, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr}, 
            (bit<32>)REG_SKETCH_SIZE);
        //meta.cm_meta.cm_1_hash = cm_1_hash;
    }

    action cm_2_hash() {
        hash(meta.cm_meta.cm_2_hash, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr},
            (bit<32>)REG_SKETCH_SIZE);
        //meta.cm_meta.cm_2_hash = cm_2_hash;
    }      

    action cm_incr() {

        cm_0_register.read(meta.cm_meta.cm_0_sketch, (bit<32>)meta.cm_meta.cm_0_hash);
        cm_1_register.read(meta.cm_meta.cm_1_sketch, (bit<32>)meta.cm_meta.cm_1_hash);
        cm_2_register.read(meta.cm_meta.cm_2_sketch, (bit<32>)meta.cm_meta.cm_2_hash);

        // Increment is made using the metadata, instead of directly on the registers.
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

	apply {
		
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
	}	

}
