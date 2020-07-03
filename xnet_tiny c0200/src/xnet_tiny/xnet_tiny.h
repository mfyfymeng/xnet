#ifndef XNET_TINY_H
#define XNET_TINY_H

#include <stdint.h>
#include <string.h>

#define XNET_CFG_PACKET_MAX_SIZE         1516
#define XNET_MAC_ADDR_SIZE               6
#define XNET_IPV4_ADDR_SIZE              4

#pragma pack (1)
typedef struct _xether_hdr_t {
	uint8_t dest[XNET_MAC_ADDR_SIZE];
	uint8_t src[XNET_MAC_ADDR_SIZE];
	uint16_t protocol; // 上层协议
}xether_hdr_t;
#pragma pack ()

typedef enum _xnet_err_t {
	XNET_ERR_OK = 0,
	XNET_ERR_IO = -1,
}xnet_err_t;

typedef struct _xnet_packet_t {
	uint16_t size;
	uint8_t* data;
	uint8_t payload[XNET_CFG_PACKET_MAX_SIZE];
}xnet_packet_t;

xnet_packet_t* xnet_alloc_for_send(uint16_t data_size);
xnet_packet_t* xnet_alloc_for_read(uint16_t data_size);

void xnet_init(void);
void xnet_poll(void);

typedef enum _xnet_protocol_t {
	XNET_PROTOCOL_ARP = 0x0806,
	XNET_PROTOCOL_IP  = 0x0800,
}xnet_protocol_t;

typedef union _xipaddr_t {
	uint8_t array[XNET_IPV4_ADDR_SIZE];
	uint32_t addr;
}xipaddr_t;

#define XARP_ENTRY_FREE                  0              

typedef struct _xarp_entry_t {
	xipaddr_t ipaddr;
	uint8_t macaddr[XNET_MAC_ADDR_SIZE];
	uint8_t state; // 这个表项的状态
	uint16_t tmo;  // 超时时间
	uint8_t retry_cnt; // 重试次数
}xarp_entry_t;

void xarp_init(void);

xnet_err_t xnet_driver_open(uint8_t* mac_addr);
xnet_err_t xnet_driver_send(xnet_packet_t* packet);
xnet_err_t xnet_driver_read(xnet_packet_t** packet);


#endif // !XNET_TINY_H
