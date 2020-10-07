control c_mv(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

	//define register arrays

	register<bit<64>>(REG_SKETCH_SIZE) reg_mv_key;
	register<int<32>>(REG_SKETCH_SIZE) reg_mv_sum;
	register<int<32>>(REG_SKETCH_SIZE) reg_mv_count;

	action hash_0() {
		hash(meta.mv.hash, 
			HashAlgorithm.crc32_custom, 
			(bit<32>)0, 
			{hdr.ipv4.src_addr, hdr.ipv4.dst_addr}, 
			(bit<32>)REG_SKETCH_SIZE);
	}    	          

	apply {

		hash_0();

		reg_mv_sum.read(meta.mv.temp_sum, meta.mv.hash);

		meta.mv.temp_sum = meta.mv.temp_sum + 1;

		reg_mv_sum.write(meta.mv.hash, meta.mv.temp_sum);

		reg_mv_key.read(meta.mv.temp_key, meta.mv.hash);
		reg_mv_count.read(meta.mv.temp_count, meta.mv.hash);

		// If the input key is different from the key stored in the register AND the related count is 0,
		// then the current input key becomes the new candidate heavy flow.
		if ((meta.mv.temp_key != hdr.ipv4.src_addr ++ hdr.ipv4.dst_addr) && (meta.mv.temp_count == 0)) {
			meta.mv.temp_key = hdr.ipv4.src_addr ++ hdr.ipv4.dst_addr;
			reg_mv_key.write(meta.mv.hash, meta.mv.temp_key);
		}

		// If the current key matches the one stored in the register then we increment the count value.
		// Else (the case where the input is different and the count is not 0), we decrement the count value (meaning that the current candidate has lost a vote count).
		if (meta.mv.temp_key == hdr.ipv4.src_addr ++ hdr.ipv4.dst_addr) {
			meta.mv.temp_count = meta.mv.temp_count + 1;
			reg_mv_count.write(meta.mv.hash, meta.mv.temp_count);
		} else {
			meta.mv.temp_count = meta.mv.temp_count - 1;
			reg_mv_count.write(meta.mv.hash, meta.mv.temp_count);
		}		  
	}
}
