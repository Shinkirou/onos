//------------------------------------------------------------------------------
// SKETCH REGISTERS
//------------------------------------------------------------------------------

// The following registers are divided by sketch, assuming their original configuration with all active sketches.

// Count-min sketch (5-tuple)
register<bit<32>>(32768) register_0;
register<bit<32>>(32768) register_1;
register<bit<32>>(32768) register_2;
register<bit<32>>(32768) register_3;

// Bitmap sketch (Src IP)
register<bit<32>>(32768) register_4;
register<bit<32>>(32768) register_5;

// Bitmap sketch (Dst IP)
register<bit<32>>(32768) register_6;
register<bit<32>>(32768) register_7;

// Bitmap sketch (Src IP Src Port)
register<bit<32>>(32768) register_8;
register<bit<32>>(32768) register_9;

// Bitmap sketch (Src IP Dst Port)
register<bit<32>>(32768) register_10;
register<bit<32>>(32768) register_11;

// Bitmap sketch (Dst IP Src Port)
register<bit<32>>(32768) register_12;
register<bit<32>>(32768) register_13;

// Bitmap sketch (Dst IP Dst Port)
register<bit<32>>(32768) register_14;
register<bit<32>>(32768) register_15;

// AMS sketch
register<bit<32>>(32768) register_16;
register<bit<32>>(32768) register_17;
register<bit<32>>(32768) register_18;
register<bit<32>>(32768) register_19;

// MV sketch
register<bit<32>>(32768) register_20;
register<bit<32>>(32768) register_21;
register<bit<32>>(32768) register_22;
register<bit<32>>(32768) register_23;

//------------------------------------------------------------------------------
// EPOCH REGISTER
//------------------------------------------------------------------------------

// 1-bit register that represents the current epoch.
// To perform an epoch change, the operator flips the bit value.
register<bit<1>>(1) register_epoch;