// Control block responsible for translating a given hash position for a virtual register
// to its corresponding position in a physical register.

control c_set_reg(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

    // Calculate the remaining space in the physical register, to determine if the current hash value fits.
    action register_setup() {
        meta.reg.index_remaining = PHYSICAL_REG_SIZE - meta.reg.current_index;
    }

    // Calculate the physical register and index corresponding to the current sketch.
    // If this action is executed, the physical register will surely advance, as the current hash value
    // (which corresponds to a virtual reg index) exceeds the remaining space in the register.
    action calculate_register_index(bit<32> sketch_hash) {

        bit<32> advance;

        // Determine the remaining hash value that spills over to the next register.
        meta.reg.current_index = sketch_hash - meta.reg.index_remaining;

        // Determine by how many physical registers we advance.
        // A hash value from a virtual register can correspond to multiple physical registers.
        // Integer Division - Right shift by a power of two corresponding to the size of each physical register.
        advance = (meta.reg.current_index + 1) >> REG_SHIFT;

        // The final physical register will correspond to the number of advances + 1 (from the initial spillover).
        meta.reg.current_register = meta.reg.current_register + advance + 1;
    }

    // Given the total number of virtual registers and the current virtual register,
    // set its corresponding physical register and starting index.
    // Defined by the operator through table rules.
    action set_reg(bit<32> current_register, bit<32> current_index) {
        meta.reg.current_register   = current_register;
        meta.reg.current_index 	    = current_index;
    }

    table t_set_reg {
        actions = {
            set_reg;
        }
    }

    apply {

        // Obtain the current physical register and starting index.
        // Calculate the remaining space available in the register, relative to the current hash value.
        t_set_reg.apply();
        register_setup();

        // If (hash < remaining space in the register), we do not increment the current register value.
        // The current index value is incremented with the hash.
        // Otherwise, the hash value spills over and we advance to the next physical registers.
        if (meta.reg.current_sketch_hash < meta.reg.index_remaining) {
            meta.reg.current_index = meta.reg.current_index + meta.reg.current_sketch_hash;
        } else {
            calculate_register_index(meta.reg.current_sketch_hash);
        }
    }
}
