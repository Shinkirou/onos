const bit<16> TYPE_IPV4 = 0x800;

const bit<8> IP_PROTO_UDP = 17;
const bit<8> IP_PROTO_TCP = 6;

#define PHYSICAL_REG_SIZE 256

// Number of virtual registers.
#define REG_12 	12
#define REG_10 	10
#define REG_8 	8
#define REG_6 	6
#define REG_4 	4
#define REG_2 	2

// Size of each virtual register given a total number of virtual registers.
#define VIRT_REG_SIZE_12 	256
#define VIRT_REG_SIZE_10 	307
#define VIRT_REG_SIZE_8  	384
#define VIRT_REG_SIZE_6	 	512
#define VIRT_REG_SIZE_4 	768
#define VIRT_REG_SIZE_2 	1536

// Defined by the physical register size, power of two.
// Used to perform integer division through right shift.
#define REG_SHIFT 8

// The following definitions represent 1) the physical registers and 2) the respective indexes 
// where the initial index for each virtual register is located.
// All possible cases are defined, given the current number of physical registers.

#define VIRT_REG_12_0 0
#define VIRT_REG_12_1 1
#define VIRT_REG_12_2 2
#define VIRT_REG_12_3 3
#define VIRT_REG_12_4 4
#define VIRT_REG_12_5 5
#define VIRT_REG_12_6 6
#define VIRT_REG_12_7 7
#define VIRT_REG_12_8 8
#define VIRT_REG_12_9 9
#define VIRT_REG_12_10 10
#define VIRT_REG_12_11 11

#define VIRT_REG_INDEX_12_0 0
#define VIRT_REG_INDEX_12_1 0
#define VIRT_REG_INDEX_12_2 0
#define VIRT_REG_INDEX_12_3 0
#define VIRT_REG_INDEX_12_4 0
#define VIRT_REG_INDEX_12_5 0
#define VIRT_REG_INDEX_12_6 0
#define VIRT_REG_INDEX_12_7 0
#define VIRT_REG_INDEX_12_8 0
#define VIRT_REG_INDEX_12_9 0
#define VIRT_REG_INDEX_12_10 0
#define VIRT_REG_INDEX_12_11 0

#define VIRT_REG_10_0 0
#define VIRT_REG_10_1 1
#define VIRT_REG_10_2 2
#define VIRT_REG_10_3 3
#define VIRT_REG_10_4 4
#define VIRT_REG_10_5 5
#define VIRT_REG_10_6 7
#define VIRT_REG_10_7 8
#define VIRT_REG_10_8 9
#define VIRT_REG_10_9 10

#define VIRT_REG_INDEX_10_0 0
#define VIRT_REG_INDEX_10_1 51
#define VIRT_REG_INDEX_10_2 102
#define VIRT_REG_INDEX_10_3 153
#define VIRT_REG_INDEX_10_4 204
#define VIRT_REG_INDEX_10_5 255
#define VIRT_REG_INDEX_10_6 50
#define VIRT_REG_INDEX_10_7 101
#define VIRT_REG_INDEX_10_8 152
#define VIRT_REG_INDEX_10_9 203

#define VIRT_REG_8_0 0
#define VIRT_REG_8_1 1
#define VIRT_REG_8_2 3
#define VIRT_REG_8_3 4
#define VIRT_REG_8_4 6
#define VIRT_REG_8_5 7
#define VIRT_REG_8_6 9
#define VIRT_REG_8_7 10

#define VIRT_REG_INDEX_8_0 0
#define VIRT_REG_INDEX_8_1 128
#define VIRT_REG_INDEX_8_2 0
#define VIRT_REG_INDEX_8_3 128
#define VIRT_REG_INDEX_8_4 0
#define VIRT_REG_INDEX_8_5 128
#define VIRT_REG_INDEX_8_6 0
#define VIRT_REG_INDEX_8_7 128

#define VIRT_REG_6_0 0
#define VIRT_REG_6_1 2
#define VIRT_REG_6_2 4
#define VIRT_REG_6_3 6
#define VIRT_REG_6_4 8
#define VIRT_REG_6_5 10

#define VIRT_REG_INDEX_6_0 0
#define VIRT_REG_INDEX_6_1 0
#define VIRT_REG_INDEX_6_2 0
#define VIRT_REG_INDEX_6_3 0
#define VIRT_REG_INDEX_6_4 0
#define VIRT_REG_INDEX_6_5 0

#define VIRT_REG_4_0 0
#define VIRT_REG_4_1 3
#define VIRT_REG_4_2 6
#define VIRT_REG_4_3 9

#define VIRT_REG_INDEX_4_0 0
#define VIRT_REG_INDEX_4_1 0
#define VIRT_REG_INDEX_4_2 0
#define VIRT_REG_INDEX_4_3 0

#define VIRT_REG_2_0 0
#define VIRT_REG_2_1 6

#define VIRT_REG_INDEX_2_0 0
#define VIRT_REG_INDEX_2_1 0
