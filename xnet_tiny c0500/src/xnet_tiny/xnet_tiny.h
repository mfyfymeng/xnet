#ifndef XNET_TINY_H
#define XNET_TINY_H

#include <stdint.h>
#include <string.h>

#define XNET_CFG_NETIF_IP                {192, 168, 254, 2} // 自己程序的ip地址是 192.168.254.2

#define XNET_CFG_PACKET_MAX_SIZE         1516
#define XNET_MAC_ADDR_SIZE               6
#define XNET_IPV4_ADDR_SIZE              4

#define XARP_CFG_ENTRY_OK_TMO            (5)
#define XARP_CFG_ENTRY_PENDING_TMO       (1)
#define XARP_CFG_MAX_RETRIES             4
#define XUDP_CFG_MAX_UDP                 10

#pragma pack (1)
typedef struct _xether_hdr_t {
	uint8_t  dest[XNET_MAC_ADDR_SIZE];
	uint8_t  src[XNET_MAC_ADDR_SIZE];
	uint16_t protocol; // 上层协议
}xether_hdr_t;

#define XARP_HW_ETHER                    0x1
#define XARP_REQUEST                     0x1
#define XARP_REPLY                       0x2

typedef struct _xarp_packet_t {
	uint16_t hw_type, pro_type;
	uint8_t  hw_len, pro_len;
	uint16_t opcode;
	uint8_t  sender_mac[XNET_MAC_ADDR_SIZE];
	uint8_t  sender_ip[XNET_IPV4_ADDR_SIZE];
	uint8_t  target_mac[XNET_MAC_ADDR_SIZE];
	uint8_t  target_ip[XNET_IPV4_ADDR_SIZE];
}xarp_packet_t;
#pragma pack ()

typedef enum _xnet_err_t {
	XNET_ERR_OK = 0,
	XNET_ERR_IO = -1,
	XNET_ERR_NONE = -2,
}xnet_err_t;

typedef struct _xnet_packet_t {
	uint16_t size;
	uint8_t* data;
	uint8_t  payload[XNET_CFG_PACKET_MAX_SIZE];
}xnet_packet_t;

xnet_packet_t* xnet_alloc_for_send(uint16_t data_size);
xnet_packet_t* xnet_alloc_for_read(uint16_t data_size);

void xnet_init(void);
void xnet_poll(void);

typedef enum _xnet_protocol_t {
	XNET_PROTOCOL_ARP = 0x0806,
	XNET_PROTOCOL_IP  = 0x0800,
	XNET_PROTOCOL_ICMP = 1,
}xnet_protocol_t;

typedef union _xipaddr_t {
	uint8_t  array[XNET_IPV4_ADDR_SIZE];
	uint32_t addr;
}xipaddr_t;

#define XARP_ENTRY_FREE                  0
#define XARP_ENTRY_OK                    1
#define XARP_ENTRY_PENDING               2

#define XARP_TIMER_PERIOD                1

typedef struct _xarp_entry_t {
	xipaddr_t ipaddr;
	uint8_t macaddr[XNET_MAC_ADDR_SIZE];
	uint8_t state;     // 这个表项的状态
	uint16_t tmo;      // 超时时间
	uint8_t retry_cnt; // 重试次数
}xarp_entry_t;

typedef uint32_t xnet_time_t;
const xnet_time_t xsys_get_time(void);

void xarp_init(void);
int  xarp_make_request(const xipaddr_t* ipaddr);
xnet_err_t xarp_make_response(xarp_packet_t* arp_packet);
void xarp_in(xnet_packet_t* packet);
void xarp_poll(void);
xnet_err_t xarp_resolve(const xipaddr_t* ipaddr, uint8_t** mac_addr);

#define XNET_VERSION_IPV4                4

#pragma pack (1)
typedef struct _xip_hdr_t {
	uint8_t  hdr_len : 4;
	uint8_t  version : 4;
	uint8_t  tos;
	uint16_t total_len;
	uint16_t id;
	uint16_t flags_fragment;
	uint8_t  ttl;
	uint8_t  protocol;
	uint16_t hdr_checksum;
	uint8_t  src_ip[XNET_IPV4_ADDR_SIZE];
	uint8_t  dest_ip[XNET_IPV4_ADDR_SIZE];
}xip_hdr_t;
#pragma pack ()

#define XNET_IP_DEFAULT_TTL              64

void xip_init(void);
void xip_in(xnet_packet_t* packet);
xnet_err_t xip_out(xnet_protocol_t protocol, xipaddr_t* dest_ip, xnet_packet_t* packet);

#pragma pack (1)
typedef struct _xicmp_hdr_t {
	uint8_t  type;
	uint8_t  code;
	uint16_t checksum;
	uint16_t id;
	uint16_t seq;
}xicmp_hdr_t;
#pragma pack ()

#define XICMP_CODE_ECHO_REQUEST          8
#define XICMP_CODE_ECHO_REPLY            0

#define XICMP_CODE_TYPE_UNREACH          3
#define XICMP_CODE_PORT_UNREACH          3
#define XICMP_CODE_PRO_UNREACH           2

void xicmp_init(void);
void xicmp_in(xipaddr_t* src_ip, xnet_packet_t* packet);
xnet_err_t xicmp_dest_unreach(uint8_t code, xip_hdr_t* ip_hdr);

typedef struct _xudp_t xudp_t;
typedef xnet_err_t(*xudp_handler_t) (xudp_t* udp, xipaddr_t* src_ip, uint16_t src_port, xnet_packet_t* packet);
struct _xudp_t {
	enum {
		XUDP_STATE_FREE,
		XUDP_STATE_USED,
	}state;

	uint16_t local_port;
	xudp_handler_t handler;
};

void xudp_init(void);

xnet_err_t xnet_driver_open(uint8_t* mac_addr);
xnet_err_t xnet_driver_send(xnet_packet_t* packet);
xnet_err_t xnet_driver_read(xnet_packet_t** packet);


#endif // !XNET_TINY_H
