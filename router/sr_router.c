/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"


void receive_ip_packet (struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface/* lent */);
int check_ip_checksum_correct(sr_ip_hdr_t *ip_hdr);
int check_icmp_checksum_correct(sr_icmp_hdr_t *icmp_header, int len);
void forward_ip_packet(struct sr_instance* sr, uint8_t* packet, unsigned char* mac);
int icmp_len(uint8_t *packet);

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d \n",len);

    /* TODO: FILL IN YOUR CODE HERE */
    sr_ethernet_hdr_t* header = eth_header(packet);
    uint16_t hdr_ether_type = ntohs(header->ether_type);

    if (hdr_ether_type == ethertype_ip) {
        printf("This is an IP packet.\n");
        receive_ip_packet(sr, packet, len, interface);
    } else if (hdr_ether_type == ethertype_arp) {
        printf("This is an ARP packet.\n");
        sr_handle_arp_pkt(sr, packet, interface);
    } else {
        printf("incorrect packet type\n");
        exit(1);
    }

}/* end sr_ForwardPacket */

void receive_ip_packet (
        struct sr_instance* sr,
        uint8_t * packet,
        unsigned int len,
        char* interface/* lent */)
{
    sr_ip_hdr_t *ip_hdr = ip_header(packet);

    if (!check_ip_checksum_correct(ip_hdr)) {
        printf("IP header checksum mismatch, ignore packet.\n");
        return;
    }

    // check whether this packet is for this router's IP
    // NOTE: checksum mismatch will be treated differently in these two cases
    char* queried_if_name = sr_is_packet_for_me(sr, ntohl(ip_hdr->ip_dst));
    if (queried_if_name) {
        printf("This IP packet is for me.\n");

        // whether this packet is TCP/UDP or ICMP
        uint8_t ip_protocol = ip_hdr->ip_p;
        if (ip_protocol == ip_protocol_icmp) {
            sr_icmp_hdr_t *icmp_hdr = icmp_header(packet);

            // verify checksum
            if (!check_icmp_checksum_correct(icmp_hdr, icmp_len(packet))) {
                printf("ICMP header checksum mismatch, ignore packet.\n");
                return;
            } else if (icmp_hdr->icmp_type == icmptype_echo_request) { // send echo if it is a echo request
                printf("Replay ICMP echo.\n");
                reply_icmp(sr, packet, icmptype_echo_reply, 0);
            } else {
                printf("ICMP type is not echo, ignore packet.\n");
            }
        } else if (ip_protocol == ip_protocol_tcp || ip_protocol == ip_protocol_udp) {
            printf("This is a UDP/TCP packet.\n");
            reply_icmp(sr, packet, icmptype_unreachable, 3);
        } else {
            printf("IP packet contains neither TCP/UDP nor ICMP, ignore packet.\n");
        }
    } else {
        printf("This IP packet should be forwarded.\n");

        if (ip_hdr->ip_ttl <= 1) {
            printf("Received packet with TTL = 1.\n");
            reply_icmp(sr, packet, icmptype_time_exceeded, 0);   
            return;      
        } 

        struct sr_arpentry *arpcache = sr_arpcache_lookup(&(sr->cache), ip_hdr->ip_dst);

        if (arpcache && arpcache->valid) { // cache hit
            printf("Cache hit\n");
            forward_ip_packet(sr, packet, arpcache->mac);
            free(arpcache);
        } else { // need to send arp request for to look up this ip
            printf("Cache miss\n");
            for (int i = 0; i < SR_ARPCACHE_SZ;i++) {
                if (sr->cache.entries[i].ip)  {
                    fprintf(stderr, "valid: %d ", sr->cache.entries[i].valid);
                    print_addr_ip_int(ntohl(sr->cache.entries[i].ip));
                }
            }

            struct sr_if* interface = lookup_interface(sr, ntohl(ip_hdr->ip_dst));
            if (interface == NULL) {
                reply_icmp(sr, packet, icmptype_unreachable, 0);
                return;
            }
            struct sr_rt* next_hop_rt = sr_LPM(sr, ntohl(ip_hdr->ip_dst));
            struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), next_hop_rt->gw.s_addr, packet, len, 
                                                       next_hop_rt->interface);
            handle_arpreq(sr, req);
        }
    }
}

int check_ip_checksum_correct(sr_ip_hdr_t *ip_hdr) {
    unsigned int header_len = ip_hdr->ip_hl;
    uint16_t checksum_val = ip_hdr->ip_sum;
    
    ip_hdr->ip_sum = 0;
    uint16_t checksum_recompute = cksum(ip_hdr, header_len * sizeof(int));
    ip_hdr->ip_sum = checksum_val;

    return checksum_val == checksum_recompute;
}

int check_icmp_checksum_correct(sr_icmp_hdr_t *icmp_header, int len) {
    uint16_t checksum_val = icmp_header->icmp_sum;

    icmp_header->icmp_sum = 0;
    uint16_t checksum_recompute = cksum(icmp_header, len);
    icmp_header->icmp_sum = checksum_val;
    return checksum_val == checksum_recompute;
}

void sr_handle_arp_pkt(struct sr_instance* sr,
        uint8_t* packet,
        char* interface){
    struct sr_arp_hdr* arp_pkt = arp_header(packet);

    // check arp op code
    if(arp_pkt->ar_op == htons(arp_op_reply)) {
        printf("This is a ARP replay.\n");
        // arp_pkt is an arp reply
        // 1. add the arp record into cache
        struct sr_arpreq* req = sr_arpcache_insert(&sr->cache, arp_pkt->ar_sha, arp_pkt->ar_sip);
        if(req){
            // if the arp reply is not for me, req will be nullptr
            // 2. send the corresponding packets in the request queue
            for(struct sr_packet* pkt = req->packets; pkt != NULL; pkt = pkt->next){
                forward_ip_packet(sr, pkt->buf, arp_pkt->ar_sha);
            }
            sr_arpreq_destroy(&sr->cache, req);
        }
    }
    if (arp_pkt->ar_op == htons(arp_op_request)){
        printf("This is a ARP request.\n");
        // 1. check if the request is for me
        char* queried_if_name = sr_is_packet_for_me(sr, ntohl(arp_pkt->ar_tip));
        if(queried_if_name){
            printf("This packet is for me.\n");
            // 2. use the given frame to reply
            // use the queried interface rather than received interface to send reply msg
            uint8_t* pkt_to_send = (uint8_t*)malloc(sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr));
            memset(pkt_to_send, 0, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr));
            struct sr_ethernet_hdr* ethernet_hdr_to_send = eth_header(pkt_to_send);
            struct sr_arp_hdr* arp_hdr_to_send = arp_header(pkt_to_send);
            // first cast and set ethernet hdr
            struct sr_if* queried_if = sr_get_interface(sr, queried_if_name);
            sr_set_ethernet_hdr(ethernet_hdr_to_send, arp_pkt->ar_sha, queried_if->addr, ethertype_arp);
            sr_set_arp_hdr(arp_hdr_to_send,
                arp_hrd_ethernet,
                0x800,
                ETHER_ADDR_LEN,
                (unsigned char)4,
                arp_op_reply,
                queried_if->addr,
                ntohl(queried_if->ip),
                arp_pkt->ar_sha,
                ntohl(arp_pkt->ar_sip));
            // http://www.networksorcery.com/enp/protocol/arp.htm#Protocol%20type

            sr_send_packet(sr, pkt_to_send, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr), queried_if_name);
            free(pkt_to_send);
        } else {
            printf("This packet is not for me, ignore it.\n");
        }      
    }
}

// if the ip in the packet is one of the interface's ip addr, return the interface's name
char* sr_is_packet_for_me(struct sr_instance* sr, uint32_t dest_ip){
    fprintf(stderr, "dest ip is: ");
    print_addr_ip_int(dest_ip);
    for(struct sr_if* interface = sr->if_list; interface != NULL; interface = interface->next){
        if(ntohl(interface->ip) == dest_ip)
            return interface->name;
    }
    return NULL;
}


void sr_set_ethernet_hdr(struct sr_ethernet_hdr* ethernet_hdr_to_send, unsigned char* dest_mac_addr, uint8_t* src_mac_addr, uint16_t ether_type){
    if(dest_mac_addr)
        memcpy(ethernet_hdr_to_send->ether_dhost, dest_mac_addr, ETHER_ADDR_LEN);
    else
        memset(ethernet_hdr_to_send->ether_dhost, 0xff, ETHER_ADDR_LEN); // broadcast
    memcpy(ethernet_hdr_to_send->ether_shost, src_mac_addr, ETHER_ADDR_LEN);
    ethernet_hdr_to_send->ether_type = htons(ether_type);
}


// will call hton on input
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
){
    struct sr_arp_hdr* arp_hdr_send = (struct sr_arp_hdr*)pkt;
    arp_hdr_send->ar_hrd = htons(out_hrd);
    arp_hdr_send->ar_pro = htons(out_pro); // ipv4
    arp_hdr_send->ar_hln = out_hln;
    arp_hdr_send->ar_pln = out_pln;
    arp_hdr_send->ar_op = htons(out_op);
    memcpy(arp_hdr_send->ar_sha, out_sha, ETHER_ADDR_LEN);
    arp_hdr_send->ar_sip = htonl(out_sip);
    if(out_tha)
        memcpy(arp_hdr_send->ar_tha, out_tha, ETHER_ADDR_LEN);
    else
        memset(arp_hdr_send->ar_tha, 0xff, ETHER_ADDR_LEN); // broadcast
    arp_hdr_send->ar_tip = htonl(out_tip);
}


void sr_set_icmp_hdr(struct sr_icmp_hdr* icmp_hdr, uint8_t* origin_packet, uint8_t icmp_type, uint8_t icmp_code){
    int len = (icmp_type == icmptype_echo_reply) ? icmp_len(origin_packet) : sizeof(sr_icmp_t3_hdr_t);

    // icmp checksum is calculated based on whole icmp msg
    
    // need to fill in the data field
    // which is IP header + the first 8 bytes of the original datagram's data.
    int ip_header_len = ip_header(origin_packet)->ip_hl * sizeof(int);
    if (icmp_type != icmptype_echo_reply) {
        uint8_t* data = ((sr_icmp_t3_hdr_t *) icmp_hdr)->data;
        memcpy(data, ip_header(origin_packet), ip_header_len);
        // if sigsegv, check here
        fprintf(stderr, "\n");
        memcpy(data + ip_header_len, (uint8_t*) ip_header(origin_packet) + ip_header_len, 8);
    } else {
        memcpy(icmp_hdr, icmp_header(origin_packet), icmp_len(origin_packet));
    }

    icmp_hdr->icmp_type = icmp_type;
    icmp_hdr->icmp_code = icmp_code;
    icmp_hdr->icmp_sum = 0; // init checksum to 0
    icmp_hdr->icmp_sum = cksum(icmp_hdr, len);
}


struct sr_rt* sr_LPM(struct sr_instance* sr, uint32_t ip){
    struct sr_rt* rst_rt = NULL;
    uint32_t max_prefix = 0;
    print_addr_ip_int(ip);
    for(struct sr_rt* rt = sr->routing_table; rt != NULL; rt = rt->next){
        uint32_t masked = ip & ntohl(rt->mask.s_addr);
        if(masked == ntohl(rt->dest.s_addr)){
            // the prefix has matched. Check if the mask is the longest
            if(ntohl(rt->mask.s_addr) >= max_prefix){
                max_prefix = ntohl(rt->mask.s_addr);
                rst_rt = rt;
            }
        }
    }
    return rst_rt;
}

void sr_set_ip_hdr(struct sr_ip_hdr* pkt_to_send,
    uint16_t ip_len,
    uint16_t ip_id,
    uint16_t ip_off,
    uint8_t ip_ttl,
    uint8_t ip_p,
    uint32_t ip_src,
    uint32_t ip_dst
){
    struct sr_ip_hdr* ip_hdr_send = (struct sr_ip_hdr*)pkt_to_send;    
    ip_hdr_send->ip_v = 4;
    ip_hdr_send->ip_hl = 5;
    ip_hdr_send->ip_tos = 0;
    ip_hdr_send->ip_len = htons(ip_len);
    ip_hdr_send->ip_id = htons(ip_id);
    ip_hdr_send->ip_off = htons(ip_off);
    ip_hdr_send->ip_ttl = ip_ttl;
    ip_hdr_send->ip_p = ip_p;
    ip_hdr_send->ip_sum = 0; // init checksum to 0
    ip_hdr_send->ip_src = htonl(ip_src);
    ip_hdr_send->ip_dst = htonl(ip_dst);
    ip_hdr_send->ip_sum = cksum(pkt_to_send, sizeof(struct sr_ip_hdr));
}

// send back icmp to the sender of the packet
void reply_icmp(struct sr_instance* sr, uint8_t* origin_packet, uint8_t type, uint8_t icmp_code) {
    int pkt_size;
    if (type == icmptype_echo_reply) {
        pkt_size = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + icmp_len(origin_packet);
    } else {
        pkt_size = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr);
    }

    uint8_t* pkt_to_send = (uint8_t*)malloc(pkt_size);
    memset(pkt_to_send, 0, pkt_size);

    // ICMP Header
    sr_set_icmp_hdr(icmp_header(pkt_to_send), origin_packet, type, icmp_code);

    // IP Header
    uint32_t dest_ip = ntohl(ip_header(origin_packet)->ip_src);

    struct sr_if* interface = lookup_interface(sr, dest_ip);

    sr_set_ip_hdr(ip_header(pkt_to_send), pkt_size - sizeof(struct sr_ethernet_hdr),
        0, 0, INIT_TTL, ip_protocol_icmp, ntohl(interface->ip), dest_ip);
    
    // Ethernet Header
    sr_set_ethernet_hdr(eth_header(pkt_to_send), eth_header(origin_packet)->ether_shost, 
                        interface->addr, ethertype_ip);
    sr_send_packet(sr, pkt_to_send, pkt_size, interface->name);
    free(pkt_to_send);
}

void decrement_ttl(sr_ip_hdr_t* header) {
    header->ip_ttl--;
    header->ip_sum = 0; // init checksum to 0
    header->ip_sum = cksum(header, header->ip_hl * sizeof(int));
}

// forward the packet to next hop
void forward_ip_packet(struct sr_instance* sr, uint8_t* packet, unsigned char* mac) {
    int pkt_size = sizeof(struct sr_ethernet_hdr) + ntohs(ip_header(packet)->ip_len);
    uint8_t* pkt_to_send = (uint8_t*)malloc(pkt_size);
    memcpy(pkt_to_send, packet, pkt_size);

    // Update IP Header
    decrement_ttl(ip_header(pkt_to_send));

    // Ethernet Header
    struct sr_if* interface = lookup_interface(sr, ntohl(ip_header(packet)->ip_dst));
    sr_set_ethernet_hdr(eth_header(pkt_to_send), mac, 
                        interface->addr, ethertype_ip);
    sr_send_packet(sr, pkt_to_send, pkt_size, interface->name);
    free(pkt_to_send);
}

struct sr_ip_hdr* ip_header(uint8_t* packet) {
    return (struct sr_ip_hdr*)(packet + sizeof(struct sr_ethernet_hdr));
}

struct sr_icmp_hdr* icmp_header(uint8_t* packet) {
    return (struct sr_icmp_hdr*)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
}

struct sr_icmp_t3_hdr* icmp_t3_header(uint8_t* packet) {
    return (struct sr_icmp_t3_hdr*)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
}

struct sr_ethernet_hdr* eth_header(uint8_t* packet) {
    return (struct sr_ethernet_hdr*) packet;
}

struct sr_arp_hdr* arp_header(uint8_t* packet) {
    return (struct sr_arp_hdr *)(packet + sizeof(struct sr_ethernet_hdr));
}

struct sr_if* lookup_interface(struct sr_instance* sr, uint32_t ip) {
    struct sr_rt* rt_send = sr_LPM(sr, ip);
    if (rt_send == NULL) {
        return NULL;
    }
    struct sr_if* if_send = sr_get_interface(sr, rt_send->interface);
    return if_send;
}

int icmp_len(uint8_t *packet) {
    return ntohs(ip_header(packet)->ip_len) - ip_header(packet)->ip_hl * sizeof(int);
}