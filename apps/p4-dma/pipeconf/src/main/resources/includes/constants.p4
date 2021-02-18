#define MAX_PORTS 255

const bit<16> TYPE_IPV4 = 0x800;

const bit<8> IP_PROTO_UDP   = 17;
const bit<8> IP_PROTO_TCP   = 6;
const bit<8> IP_PROTO_ICMP  = 1;

typedef bit<9> port_t;

const port_t CPU_PORT = 255;

#define PHYSICAL_REG_SIZE 32768

// Defined by the physical register size, power of two.
// Used to perform integer division through right shift.
#define REG_SHIFT 15
