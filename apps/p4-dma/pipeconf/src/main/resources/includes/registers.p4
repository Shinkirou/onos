//------------------------------------------------------------------------------
// SKETCH REGISTERS
//------------------------------------------------------------------------------

// The following registers are divided by sketch, assuming their original configuration with all active sketches.

// Count-min sketch (5-tuple)
register<bit<32>>(256) 	register_0;
register<bit<32>>(256) 	register_1;
register<bit<32>>(256) 	register_2;
register<bit<32>>(256) 	register_3;

// Count-min sketch (IP addresses)
register<bit<32>>(256) 	register_4;
register<bit<32>>(256) 	register_5;
register<bit<32>>(256) 	register_6;
register<bit<32>>(256) 	register_7;

// Bitmap sketch (Source IP)
register<bit<32>>(256) 	register_8;
register<bit<32>>(256) 	register_9;

// Bitmap sketch (Destination IP)
register<bit<32>>(256) 	register_10;
register<bit<32>>(256) 	register_11;

//------------------------------------------------------------------------------
// EPOCH REGISTER
//------------------------------------------------------------------------------

// 1-bit register that represents the current epoch.
// To perform an epoch change, the operator flips the bit value.
register<bit<1>>(1) register_epoch;