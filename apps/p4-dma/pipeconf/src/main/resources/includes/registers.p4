//------------------------------------------------------------------------------
// SKETCH REGISTERS
//------------------------------------------------------------------------------

// The following registers are divided by sketch, assuming their original configuration with all active sketches.

// Count-min sketch (IP src, IP dst)
register<bit<32>>(32768) register_0;
register<bit<32>>(32768) register_1;
register<bit<32>>(32768) register_2;
register<bit<32>>(32768) register_3;

// Count-min sketch (IP src, IP dst, port dst)
register<bit<32>>(32768) register_4;
register<bit<32>>(32768) register_5;
register<bit<32>>(32768) register_6;
register<bit<32>>(32768) register_7;

// Count-min sketch (IP src, IP Dst, TCP flags)
register<bit<32>>(32768) register_8;
register<bit<32>>(32768) register_9;
register<bit<32>>(32768) register_10;
register<bit<32>>(32768) register_11;

// Count-min sketch (IP src, IP dst, proto)
register<bit<32>>(32768) register_12;
register<bit<32>>(32768) register_13;
register<bit<32>>(32768) register_14;
register<bit<32>>(32768) register_15;

// Bitmap sketch (IP src)
register<bit<32>>(32768) register_16;
register<bit<32>>(32768) register_17;

// Bitmap sketch (IP dst)
register<bit<32>>(32768) register_18;
register<bit<32>>(32768) register_19;

// Bitmap sketch (IP src, port src)
register<bit<32>>(32768) register_20;
register<bit<32>>(32768) register_21;

// Bitmap sketch (IP src, port dst)
register<bit<32>>(32768) register_22;
register<bit<32>>(32768) register_23;

// Bitmap sketch (IP dst, port src)
register<bit<32>>(32768) register_24;
register<bit<32>>(32768) register_25;

// Bitmap sketch (IP dst, port dst)
register<bit<32>>(32768) register_26;
register<bit<32>>(32768) register_27;

// AMS sketch
register<bit<32>>(32768) register_28;
register<bit<32>>(32768) register_29;
register<bit<32>>(32768) register_30;
register<bit<32>>(32768) register_31;

// MV sketch
register<bit<32>>(32768) register_32;
register<bit<32>>(32768) register_33;
register<bit<32>>(32768) register_34;
register<bit<32>>(32768) register_35;

//------------------------------------------------------------------------------
// EPOCH REGISTER
//------------------------------------------------------------------------------

// 1-bit register that represents the current epoch.
// To perform an epoch change, the operator flips the bit value.
register<bit<1>>(1) register_epoch;