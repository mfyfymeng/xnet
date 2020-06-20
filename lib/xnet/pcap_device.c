#include <memory.h>
#include "pcap_device.h"

#include <winsock.h>
#include <tchar.h>
#include <time.h>

#pragma comment(lib, "ws2_32.lib")

#pragma comment(lib, "..\\lib\\npcap\\Lib\\x64\\Packet.lib")  
#pragma comment(lib, "..\\lib\\npcap\\Lib\\x64\\wpcap.lib") 

static int load_pcap_lib() {
    static int dll_loaded = 0;
    _TCHAR  npcap_dir[512];
    int size;

    if (dll_loaded) {
        return 0;
    }

    size = GetSystemDirectory(npcap_dir, 480);
    if (!size) {
        fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
        return -1;
    }

    _tcscat_s(npcap_dir, 512, _T("\\Npcap"));
    if (SetDllDirectory(npcap_dir) == 0) {
        fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
        return -1;
    }

    dll_loaded = 1;
    return 0;
}

static int pcap_find_device(const char* ip, char* name_buf) {
    char err_buf[PCAP_ERRBUF_SIZE];
    pcap_if_t* pcap_if_list = NULL;
    struct in_addr dest_ip;
    pcap_if_t* item;

    inet_pton(AF_INET, ip, &dest_ip);

    int err = pcap_findalldevs(&pcap_if_list, err_buf);
    if (err < 0) {
        pcap_freealldevs(pcap_if_list);
        return -1;
    }

    for (item = pcap_if_list; item != NULL; item = item->next) {
        if (item->addresses == NULL) {
            continue;
        }

        for (struct pcap_addr* pcap_addr = item->addresses; pcap_addr != NULL; pcap_addr = pcap_addr->next) {
            struct sockaddr_in* curr_addr;
            struct sockaddr* sock_addr = pcap_addr->addr;

            if (sock_addr->sa_family != AF_INET) {
                continue;
            }

            curr_addr = ((struct sockaddr_in*)sock_addr);
            if (curr_addr->sin_addr.s_addr == dest_ip.s_addr) {
                strcpy(name_buf, item->name);
                pcap_freealldevs(pcap_if_list);
                return 0;
            }
        }
    }

    pcap_freealldevs(pcap_if_list);
    return -1;
}

static int pcap_show_list(void) {
    char err_buf[PCAP_ERRBUF_SIZE];
    pcap_if_t* pcapif_list = NULL;
    int count = 0;
    
    int err = pcap_findalldevs(&pcapif_list, err_buf);
    if (err < 0) {
        fprintf(stderr, "pcap_show_list: find all net list failed:%s\n", err_buf);
        pcap_freealldevs(pcapif_list);
        return -1;
    }

    printf("pcap_show_list: card list\n");
    
    for (pcap_if_t* item = pcapif_list; item != NULL; item = item->next) {
        if (item->addresses == NULL) {
            continue;
        }

        for (struct pcap_addr* pcap_addr = item->addresses; pcap_addr != NULL; pcap_addr = pcap_addr->next) {
            char str[INET_ADDRSTRLEN];
            struct sockaddr_in* ip_addr;

            struct sockaddr* sockaddr = pcap_addr->addr;
            if (sockaddr->sa_family != AF_INET) {
                continue;
            }

            ip_addr = (struct sockaddr_in*)sockaddr;
            printf("card %d: IP:%s name: %s, \n\n",
                count++,
                item->description == NULL ? "" : item->description,
                inet_ntop(AF_INET, &ip_addr->sin_addr, str, sizeof(str))
            );
            break;
        }
    }

    pcap_freealldevs(pcapif_list);

    if ((pcapif_list == NULL) || (count == 0)) {
        fprintf(stderr, "pcap_show_list: no available card!\n");
        return -1;
    }

    return 0;
}

pcap_t* pcap_device_open(const char* ip, const uint8_t* mac_addr, uint8_t poll_mode) {
    char err_buf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;
    char filter_exp[256];
    char name_buf[256];
    pcap_t* pcap;

    if (load_pcap_lib() < 0) {
        fprintf(stderr, "pcap_open: load pcap dll failed! install it first\n");
        return (pcap_t*)0;
    }

    if (pcap_find_device(ip, name_buf) < 0) {
        fprintf(stderr, "pcap_open: no net card has ip: %s, use the following:\n", ip);
        pcap_show_list();
        return (pcap_t*)0;
    }

    if (pcap_lookupnet(name_buf, &net, &mask, err_buf) == -1) {
        printf("pcap_open: can't find use net card: %s\n", name_buf);
        net = 0;
        mask = 0;
    }

    pcap = pcap_open_live(name_buf, 65536, 1, 0, err_buf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open: create pcap failed %s\n net card name: %s\n", err_buf, name_buf);
        fprintf(stderr, "Use the following:\n");
        pcap_show_list();
        return (pcap_t*)0;
    }
    
    if (pcap_setnonblock(pcap, 1, err_buf) != 0) {
        fprintf(stderr, "pcap_open: set none block failed: %s\n", pcap_geterr(pcap));
        return (pcap_t*)0;
    }
    
    if (pcap_setdirection(pcap, PCAP_D_IN) != 0) {
        fprintf(stderr, "pcap_open: set direction failed: %s\n", pcap_geterr(pcap));
    }
    
    sprintf(filter_exp,
        "(ether dst %02x:%02x:%02x:%02x:%02x:%02x or ether broadcast) and (not ether src %02x:%02x:%02x:%02x:%02x:%02x)",
        mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5],
        mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
    if (pcap_compile(pcap, &fp, filter_exp, 0, net) == -1) {
        printf("pcap_open: couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(pcap));
        return (pcap_t*)0;
    }
    if (pcap_setfilter(pcap, &fp) == -1) {
        printf("pcap_open: couldn't install filter %s: %s\n", filter_exp, pcap_geterr(pcap));
        return (pcap_t*)0;
    }

    return pcap;
}

void pcap_device_close(pcap_t* pcap) {
    if (pcap == (pcap_t*)0) {
        fprintf(stderr, "pcap = 0");
        pcap_show_list();
        return;
    }
    pcap_close(pcap);
}

uint32_t pcap_device_send(pcap_t* pcap, const uint8_t* buffer, uint32_t length) {
    if (pcap_sendpacket(pcap, buffer, length) == -1) {
        fprintf(stderr, "pcap send: send packet failed!:%s\n", pcap_geterr(pcap));
        fprintf(stderr, "pcap send: pcaket size %d\n", length);
        return 0;
    }

    return 0;
}

uint32_t pcap_device_read(pcap_t* pcap, uint8_t* buffer, uint32_t length) {
    int err;
    struct pcap_pkthdr* pkthdr;
    const uint8_t* pkt_data;

    err = pcap_next_ex(pcap, &pkthdr, &pkt_data);
    if (err == 0) {
        return 0;
    }
    else if (err == 1) {
        memcpy(buffer, pkt_data, pkthdr->len);
        return pkthdr->len;
    }

    fprintf(stderr, "pcap_read: reading packet failed!:%s", pcap_geterr(pcap));
    return 0;
}
