#define MAX_PORTS 255

const bit<8> IP_PROTO_UDP = 17;
const bit<8> IP_PROTO_TCP = 6;

const bit<16> ETH_TYPE_IPV4 = 0x800;

typedef bit<9> port_t;
const port_t CPU_PORT = 255;