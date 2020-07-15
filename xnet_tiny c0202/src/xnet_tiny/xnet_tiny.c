#include "xnet_tiny.h"

static const xipaddr_t netif_ipaddr = XNET_CFG_NETIF_IP; // 程序创建了一张虚拟网卡，放在 netif_ipaddr 中
static const uint8_t   ether_broadcast[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }; // 广播地址

#define min(a, b)                          ((a) > (b) ? (b) : (a))
#define swap_order16(v)                    ((((v) & 0xFF) << 8) | (((v) >> 8) & 0xFF))
#define xipaddr_is_equal_buf(addr, buf)    (memcmp((addr)->array, (buf), XNET_IPV4_ADDR_SIZE) == 0)

static uint8_t netif_mac[XNET_MAC_ADDR_SIZE];
static xnet_packet_t tx_packet, rx_packet;
static xarp_entry_t arp_entry;

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
	packet->size = min(packet->size, size);
}

static xnet_err_t ethernet_init(void) {
	xnet_err_t err = xnet_driver_open(netif_mac);

	if (err) return err;

	return xarp_make_request(&netif_ipaddr);
}

static xnet_err_t ethernet_out_to(xnet_protocol_t protocol, const uint8_t* mac_addr, xnet_packet_t* packet) {
	xether_hdr_t* ether_hdr;

	add_header(packet, sizeof(xether_hdr_t));
	ether_hdr = (xether_hdr_t*)packet->data;
	memcpy(ether_hdr->dest, mac_addr, XNET_MAC_ADDR_SIZE);
	memcpy(ether_hdr->src, netif_mac, XNET_MAC_ADDR_SIZE);
	ether_hdr->protocol = swap_order16(protocol);

	return xnet_driver_send(packet);
}

static void ethernet_in(xnet_packet_t* packet) {
	xether_hdr_t* ether_hdr;
	uint16_t protocol;
	
	if (packet->size <= sizeof(xether_hdr_t)) {
		return;
	}

	ether_hdr = (xether_hdr_t*)packet->data;
	protocol = swap_order16(ether_hdr->protocol);
	switch (protocol) {
	case XNET_PROTOCOL_ARP:
		remove_header(packet, sizeof(xether_hdr_t));
		xarp_in(packet);
		break;
	case XNET_PROTOCOL_IP:
		break;
	}
}

static void ethernet_poll(void) {
	xnet_packet_t* packet;

	if (xnet_driver_read(&packet) == XNET_ERR_OK) {
		ethernet_in(packet);
	}
}

void xarp_init(void) {
	arp_entry.state = XARP_ENTRY_FREE;
}

int xarp_make_request(const xipaddr_t* ipaddr) {
	xnet_packet_t* packet = xnet_alloc_for_send(sizeof(xarp_packet_t));
	xarp_packet_t* arp_packet = (xarp_packet_t*)packet->data;

	arp_packet->hw_type  = swap_order16(XARP_HW_ETHER);
	arp_packet->pro_type = swap_order16(XNET_PROTOCOL_IP);
	arp_packet->hw_len   = XNET_MAC_ADDR_SIZE;
	arp_packet->pro_len  = XNET_IPV4_ADDR_SIZE;
	arp_packet->opcode   = swap_order16(XARP_REQUEST);
	memcpy(arp_packet->sender_mac, netif_mac, XNET_MAC_ADDR_SIZE);
	memcpy(arp_packet->sender_ip, netif_ipaddr.array, XNET_IPV4_ADDR_SIZE);
	memset(arp_packet->target_mac, 0, XNET_MAC_ADDR_SIZE);
	memcpy(arp_packet->target_ip, ipaddr->array, XNET_IPV4_ADDR_SIZE);

	return ethernet_out_to(XNET_PROTOCOL_ARP, ether_broadcast, packet);
}

xnet_err_t xarp_make_response(xarp_packet_t* arp_packet) {
	xnet_packet_t* packet = xnet_alloc_for_send(sizeof(xarp_packet_t));
	xarp_packet_t* response_packet = (xarp_packet_t*)packet->data;

	response_packet->hw_type = swap_order16(XARP_HW_ETHER);
	response_packet->pro_type = swap_order16(XNET_PROTOCOL_IP);
	response_packet->hw_len = XNET_MAC_ADDR_SIZE;
	response_packet->pro_len = XNET_IPV4_ADDR_SIZE;
	response_packet->opcode = swap_order16(XARP_REPLY);
	memcpy(response_packet->sender_mac, netif_mac, XNET_MAC_ADDR_SIZE);
	memcpy(response_packet->sender_ip, netif_ipaddr.array, XNET_IPV4_ADDR_SIZE);
	memcpy(response_packet->target_mac, arp_packet->sender_mac, XNET_MAC_ADDR_SIZE);
	memcpy(response_packet->target_ip, arp_packet->sender_ip, XNET_IPV4_ADDR_SIZE);

	return ethernet_out_to(XNET_PROTOCOL_ARP, arp_packet->sender_mac, packet);
}

static void update_arp_entry(uint8_t* src_ip, uint8_t* mac_addr) {
	memcpy(arp_entry.ipaddr.array, src_ip, XNET_IPV4_ADDR_SIZE);
	memcpy(arp_entry.macaddr, mac_addr, XNET_MAC_ADDR_SIZE);
	arp_entry.state = XARP_ENTRY_OK;
}

void xarp_in(xnet_packet_t* packet) {
	if (packet->size >= sizeof(xarp_packet_t)) {
		xarp_packet_t* arp_packet = (xarp_packet_t*)packet->data;
		uint16_t opcode = swap_order16(arp_packet->opcode);
		
		if ((swap_order16(arp_packet->hw_type) != XARP_HW_ETHER) ||
			(arp_packet->hw_len != XNET_MAC_ADDR_SIZE) ||
			(swap_order16(arp_packet->pro_type) != XNET_PROTOCOL_IP) ||
			(arp_packet->pro_len != XNET_IPV4_ADDR_SIZE) ||
			((opcode != XARP_REQUEST) && (opcode != XARP_REPLY))) {
			return;
		}

		if (!xipaddr_is_equal_buf(&netif_ipaddr, arp_packet->target_ip)) {
			return;
		}

		switch (opcode) {
		case XARP_REQUEST:
			xarp_make_response(arp_packet);
			update_arp_entry(arp_packet->sender_ip, arp_packet->sender_mac);
			break;
		case XARP_REPLY:
			break;
		}
	}
}

void xnet_init(void) {
	ethernet_init();
	xarp_init();
}

void xnet_poll(void) {
	ethernet_poll();
}
