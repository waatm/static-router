/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "sr_arpcache.h"

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024

/* forward declare */
struct sr_if;
struct sr_rt;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance
{
    int  sockfd;   /* socket to server */
    char user[32]; /* user name */
    char host[32]; /* host name */ 
    char template[30]; /* template name if any */
    unsigned short topo_id;
    struct sockaddr_in sr_addr; /* address to server */
    struct sr_if* if_list; /* list of interfaces */
    struct sr_rt* routing_table; /* routing table */
    struct sr_arpcache cache;   /* ARP cache */
    pthread_attr_t attr;
    FILE* logfile;
};

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
int sr_read_from_server(struct sr_instance* );

/* -- sr_router.c -- */
void sr_init(struct sr_instance* );
void sr_handlepacket(struct sr_instance* , uint8_t * , unsigned int , char* );

/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance* , const char* );
void sr_set_ether_ip(struct sr_instance* , uint32_t );
void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
void sr_print_if_list(struct sr_instance* );

// my fxn
void sr_handle_arp_pkt(struct sr_instance* sr, uint8_t* packet, char* interface);
char* sr_is_packet_for_me(struct sr_instance* sr, uint32_t dest_ip);
void sr_set_ethernet_hdr(struct sr_ethernet_hdr* ethernet_hdr_to_send, unsigned char* dest_mac_addr, uint8_t* src_mac_addr, uint16_t ether_type);
void sr_set_arp_hdr(struct sr_arp_hdr* pkt,
    unsigned short out_hrd,
    unsigned short out_pro,
    unsigned char out_hln,
    unsigned char out_pln,
    unsigned short out_op,
    unsigned char* out_sha,
    uint32_t out_sip,
    unsigned char* out_tha,
    uint32_t out_tip
);
void sr_set_icmp_hdr(struct sr_icmp_hdr* icmp_hdr, uint8_t* oringin_packet, uint8_t icmp_type, uint8_t icmp_code);
struct sr_rt* sr_LPM(struct sr_instance* sr, uint32_t ip);
void sr_set_ip_hdr(struct sr_ip_hdr* pkt_to_send,
    uint16_t ip_len,
    uint16_t ip_id,
    uint16_t ip_off,
    uint8_t ip_ttl,
    uint8_t ip_p,
    uint32_t ip_src,
    uint32_t ip_dst
);

void reply_icmp(struct sr_instance* sr, uint8_t* origin_packet, uint8_t type, uint8_t icmp_code);
struct sr_ip_hdr* ip_header(uint8_t* packet);
struct sr_icmp_hdr* icmp_header(uint8_t* packet);
struct sr_icmp_t3_hdr* icmp_t3_header(uint8_t* packet);
struct sr_ethernet_hdr* eth_header(uint8_t* packet);
struct sr_arp_hdr* arp_header(uint8_t* packet);
struct sr_if* lookup_interface(struct sr_instance* sr, uint32_t ip);

#endif /* SR_ROUTER_H */
