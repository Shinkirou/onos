control c_cm_5t(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

	register<bit<32>>(REG_SKETCH_SIZE)  reg_cm_5t_0;
	register<bit<32>>(REG_SKETCH_SIZE)  reg_cm_5t_1;  
	register<bit<32>>(REG_SKETCH_SIZE)  reg_cm_5t_2;  
	register<bit<32>>(REG_SKETCH_SIZE)  reg_cm_5t_final;    

	action hash_0() {
		hash(meta.cm_5t.hash_0, 
			HashAlgorithm.crc32_custom, 
			(bit<32>)0, 
			{hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.meta.l4_src_port, (bit<32>)meta.meta.l4_dst_port}, 
			(bit<32>)REG_SKETCH_SIZE);
	}

	action hash_1() {
		hash(meta.cm_5t.hash_1, 
			HashAlgorithm.crc32_custom, 
			(bit<32>)0, 
			{hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.meta.l4_src_port, (bit<32>)meta.meta.l4_dst_port}, 
			(bit<32>)REG_SKETCH_SIZE);
	}

	action hash_2() {
		hash(meta.cm_5t.hash_2, 
			HashAlgorithm.crc32_custom, 
			(bit<32>)0, 
			{hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.protocol, (bit<32>)meta.meta.l4_src_port, (bit<32>)meta.meta.l4_dst_port}, 
			(bit<32>)REG_SKETCH_SIZE);
	}

	action cm_incr() {

		reg_cm_5t_0.read(meta.cm_5t.sketch_0, (bit<32>)meta.cm_5t.hash_0);
		reg_cm_5t_1.read(meta.cm_5t.sketch_1, (bit<32>)meta.cm_5t.hash_1);
		reg_cm_5t_2.read(meta.cm_5t.sketch_2, (bit<32>)meta.cm_5t.hash_2);        

		// Increment is made using the metadata, instead of directly on the registers.
		// This allows us to perform the final value comparison on the apply{} block.

		meta.cm_5t.sketch_0 = meta.cm_5t.sketch_0 + 1;
		meta.cm_5t.sketch_1 = meta.cm_5t.sketch_1 + 1;
		meta.cm_5t.sketch_2 = meta.cm_5t.sketch_2 + 1;

		reg_cm_5t_0.write((bit<32>)meta.cm_5t.hash_0, meta.cm_5t.sketch_0);
		reg_cm_5t_1.write((bit<32>)meta.cm_5t.hash_1, meta.cm_5t.sketch_1);
		reg_cm_5t_2.write((bit<32>)meta.cm_5t.hash_2, meta.cm_5t.sketch_2);        
	}

	action cm_register_write() {
		reg_cm_5t_final.write((bit<32>)meta.cm_5t.hash_2, meta.cm_5t.sketch_final);
	}

	apply {
		
		// Count-min sketch.
		hash_0();
		hash_1();
		hash_2();
	
		// Increment the value on all registers.
		cm_incr();

		// Compare the current value on all registers and identify the smallest.
		meta.cm_5t.sketch_final = meta.cm_5t.sketch_0;

		if (meta.cm_5t.sketch_final > meta.cm_5t.sketch_1) {
			meta.cm_5t.sketch_final = meta.cm_5t.sketch_1;
		}
		
		if (meta.cm_5t.sketch_final > meta.cm_5t.sketch_2) {
			meta.cm_5t.sketch_final = meta.cm_5t.sketch_2;
		}

		// Write the smallest value to the final count-min register.
		cm_register_write();
	}

}
