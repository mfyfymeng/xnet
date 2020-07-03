#ifndef XNET_TINY_H
#define XNET_TINY_H

#include <stdint.h>

#define XNET_CFG_PACKET_MAX_SIZE         1516

typedef struct _xnet_packet_t {
	uint16_t size;
	uint8_t* data;
	uint8_t payload[XNET_CFG_PACKET_MAX_SIZE];
}xnet_packet_t;

xnet_packet_t* xnet_alloc_for_send(uint16_t data_size);
xnet_packet_t* xnet_alloc_for_read(uint16_t data_size);

void xnet_init(void);
void xnet_poll(void);



#endif // !XNET_TINY_H
