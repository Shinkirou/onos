//------------------------------------------------------------------------------
// SKETCH REGISTERS
//------------------------------------------------------------------------------

// The following registers are divided by sketch, assuming their original configuration with all active sketches.

// Count-min sketch (IP src, IP dst) - packet count
register<bit<32>>(REG_SIZE) reg_0;
register<bit<32>>(REG_SIZE) reg_1;
register<bit<32>>(REG_SIZE) reg_2;
register<bit<32>>(REG_SIZE) reg_3;

// Count-min sketch (IP src, IP dst) - packet length
register<bit<32>>(REG_SIZE) reg_4;
register<bit<32>>(REG_SIZE) reg_5;
register<bit<32>>(REG_SIZE) reg_6;
register<bit<32>>(REG_SIZE) reg_7;

// Count-min sketch (IP src, IP dst, port dst) - packet count
register<bit<32>>(REG_SIZE) reg_8;
register<bit<32>>(REG_SIZE) reg_9;
register<bit<32>>(REG_SIZE) reg_10;
register<bit<32>>(REG_SIZE) reg_11;

// Count-min sketch (IP src, IP dst, port dst) - packet length
register<bit<32>>(REG_SIZE) reg_12;
register<bit<32>>(REG_SIZE) reg_13;
register<bit<32>>(REG_SIZE) reg_14;
register<bit<32>>(REG_SIZE) reg_15;

// Count-min sketch (IP src, IP Dst, TCP flags) - packet count
register<bit<32>>(REG_SIZE) reg_16;
register<bit<32>>(REG_SIZE) reg_17;
register<bit<32>>(REG_SIZE) reg_18;
register<bit<32>>(REG_SIZE) reg_19;

// Count-min sketch (IP src, IP Dst, TCP flags) - packet length
register<bit<32>>(REG_SIZE) reg_20;
register<bit<32>>(REG_SIZE) reg_21;
register<bit<32>>(REG_SIZE) reg_22;
register<bit<32>>(REG_SIZE) reg_23;

// Count-min sketch (IP src, IP dst, proto) - packet count
register<bit<32>>(REG_SIZE) reg_24;
register<bit<32>>(REG_SIZE) reg_25;
register<bit<32>>(REG_SIZE) reg_26;
register<bit<32>>(REG_SIZE) reg_27;

// Count-min sketch (IP src, IP dst, proto) - packet length
register<bit<32>>(REG_SIZE) reg_28;
register<bit<32>>(REG_SIZE) reg_29;
register<bit<32>>(REG_SIZE) reg_30;
register<bit<32>>(REG_SIZE) reg_31;

// Bitmap sketch (IP src)
register<bit<32>>(REG_SIZE) reg_32;
register<bit<32>>(REG_SIZE) reg_33;

// Bitmap sketch (IP dst)
register<bit<32>>(REG_SIZE) reg_34;
register<bit<32>>(REG_SIZE) reg_35;

// Bitmap sketch (IP src, port src)
register<bit<32>>(REG_SIZE) reg_36;
register<bit<32>>(REG_SIZE) reg_37;

// Bitmap sketch (IP src, port dst)
register<bit<32>>(REG_SIZE) reg_38;
register<bit<32>>(REG_SIZE) reg_39;

// Bitmap sketch (IP dst, port src)
register<bit<32>>(REG_SIZE) reg_40;
register<bit<32>>(REG_SIZE) reg_41;

// Bitmap sketch (IP dst, port dst)
register<bit<32>>(REG_SIZE) reg_42;
register<bit<32>>(REG_SIZE) reg_43;

// AMS sketch
register<bit<32>>(REG_SIZE) reg_44;
register<bit<32>>(REG_SIZE) reg_45;
register<bit<32>>(REG_SIZE) reg_46;
register<bit<32>>(REG_SIZE) reg_47;

// MV sketch
register<bit<32>>(REG_SIZE) reg_48;
register<bit<32>>(REG_SIZE) reg_49;
register<bit<32>>(REG_SIZE) reg_50;
register<bit<32>>(REG_SIZE) reg_51;

//------------------------------------------------------------------------------
// TIMESTAMP REGISTER
//------------------------------------------------------------------------------

// Stores old packet timestamps required for the damped window statistics calculation.

register<int<48>>(REG_SIZE) reg_ts_old;