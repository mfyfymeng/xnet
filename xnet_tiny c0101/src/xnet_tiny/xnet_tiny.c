#include "xnet_tiny.h"

#define min(a, b)           ((a) > (b) ? (b) : (a))

static xnet_packet_t tx_packet, rx_packet;

xnet_packet_t* xnet_alloc_for_send(uint16_t data_size) {
	tx_packet.data = tx_packet.payload + XNET_CFG_PACKET_MAX_SIZE - data_size;
	tx_packet.size = data_size;
	return &tx_packet;
}

xnet_packet_t* xnet_alloc_for_read(uint16_t data_size) {
	rx_packet.data = rx_packet.payload;
	rx_packet.size = data_size;
	return &rx_packet;
}

static void add_header(xnet_packet_t* packet, uint16_t header_size) {
	packet->data -= header_size;
	packet->size += header_size;
}

static void remove_header(xnet_packet_t* packet, uint16_t header_size) {
	packet->data += header_size;
	packet->size -= header_size;
}

static void truncate_packet(xnet_packet_t* packet, uint16_t size) {
	packet->size -= min(packet->size, size);
}

void xnet_init(void) {
	char mac_addr[8];

	xnet_driver_open(mac_addr);
}

void xnet_poll(void) {
	xnet_packet_t* packet;
	xnet_err_t err;
	
	err = xnet_driver_read(&packet);
	if (err == XNET_ERR_OK) {
		packet->data[0] = 'a';
		packet->data[1] = 'b';
		packet->data[2] = 'c';

		xnet_driver_send(packet);
	}
}
