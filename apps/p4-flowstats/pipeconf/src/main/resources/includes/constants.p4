#define MAX_PORTS 255

const bit<8> IP_PROTO_UDP 	= 17;
const bit<8> IP_PROTO_TCP 	= 6;
const bit<8> IP_PROTO_ICMP 	= 1;

const bit<16> ETH_TYPE_IPV4 = 0x800;
const bit<32> MAX_INT = 0xFFFFFFFF;

const bit<32> REG_SKETCH_SIZE = 262144;

typedef bit<9> port_t;

const port_t CPU_PORT = 255;
