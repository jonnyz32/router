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

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include <stdlib.h>
#include <string.h>

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

#if 0
  struct sr_arp_hdr {
    unsigned short  ar_hrd;             /* format of hardware address   */
    unsigned short  ar_pro;             /* format of protocol address   */
    unsigned char   ar_hln;             /* length of hardware address   */
    unsigned char   ar_pln;             /* length of protocol address   */
    unsigned short  ar_op;              /* ARP opcode (command)         */
    unsigned char   ar_sha[ETHER_ADDR_LEN];   /* sender hardware address      */
    uint32_t        ar_sip;             /* sender IP address            */
    unsigned char   ar_tha[ETHER_ADDR_LEN];   /* target hardware address      */
    uint32_t        ar_tip;             /* target IP address            */
} __attribute__ ((packed)) ;

struct sr_icmp_hdr {
  uint8_t icmp_type;
  uint8_t icmp_code;
  uint16_t icmp_sum;
}

struct sr_ip_hdr {
    uint8_t ip_tos;			/* type of service */
    uint16_t ip_len;			/* total length */
    uint16_t ip_id;			/* identification */
    uint16_t ip_off;			/* fragment offset field */
#define IP_RF 0x8000      /* reserved fragment flag */
#define IP_DF 0x4000      /* dont fragment flag */
#define IP_MF 0x2000      /* more fragments flag */
#define IP_OFFMASK 0x1fff /* mask for fragmenting bits */
    uint8_t ip_ttl;			/* time to live */
    uint8_t ip_p;			/* protocol */
    uint16_t ip_sum;			/* checksum */
    uint32_t ip_src, ip_dst;	/* source and dest address */
}

struct sr_ethernet_hdr
{
#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN 6
#endif
    uint8_t  ether_dhost[ETHER_ADDR_LEN];    /* destination ethernet address */
    uint8_t  ether_shost[ETHER_ADDR_LEN];    /* source ethernet address */
    uint16_t ether_type;                     /* packet type ID */
} __attribute__ ((packed)) ;
typedef struct sr_ethernet_hdr sr_ethernet_hdr_t;
#endif

void sr_init(struct sr_instance *sr)
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
void create_icmp_packet(struct sr_instance *sr, int type, int code, char *interface_to_send_from, uint32_t new_dest_ip);

struct sr_if *sr_get_interface_with_longest_match(struct sr_instance *sr, uint32_t destination_ip)
{
  struct sr_rt *entry;
  char *interface;
  char *default_gateway;
  uint32_t longest_match_length = 0;

  for (entry = sr->routing_table; entry != NULL; entry = entry->next)
  {
    if (entry->dest.s_addr == 0)
    {
      default_gateway = entry->interface;
    }
    uint32_t mask = entry->mask.s_addr;
    /*     uint32_t network_ip = gateway_ip & mask;
 */
    uint32_t network_ip = entry->dest.s_addr & mask;

    if (~(~network_ip ^ destination_ip) == 0)
    {
      /* Entry matches*/
      if (mask > longest_match_length)
      {
        longest_match_length = mask;
        interface = entry->interface;
      }
    }
  }
  return longest_match_length > 0 ? sr_get_interface(sr, interface) : sr_get_interface(sr, default_gateway);
}

int sanity_check_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, int needs_forwarding)
{
  /* Return -1 if the packet has a problem, 1 if the packet is good*/
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  if (len > 1500 || len < 20)
  {
    printf("Discarding packet. Packet length: %u\n", len);
    return -1;
  }

  uint16_t ip_cksum_recieved = iphdr->ip_sum;
  iphdr->ip_sum = 0;
  uint16_t ip_cksum_new = cksum(packet + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t));
  if (ip_cksum_new != ip_cksum_recieved)
  {
    printf("Discarding packet. Ip checksum is incorrect\n");
    return -1;
  }

  if (iphdr->ip_p == 1)
  {
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    uint16_t icmp_cksum_recieved = icmp_hdr->icmp_sum;
    icmp_hdr->icmp_sum = 0;
    uint16_t icmp_cksum_new = cksum(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t),
                                    len - (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)));

    if (icmp_cksum_new != icmp_cksum_recieved)
    {
      printf("Discarding packet. Icmp checksum is incorrect\n");
      return -1;
    }
  }

  iphdr->ip_ttl -= 1;
  if (needs_forwarding == 1 && iphdr->ip_ttl == 0)
  {
    printf("Discarding packet. TTL is 0\n");
    struct sr_if *interface_to_send_message_back_from = sr_get_interface_with_longest_match(sr, iphdr->ip_src);
    create_icmp_packet(sr, 11, 0, interface_to_send_message_back_from->name, iphdr->ip_src);
    return -1;
  }
  iphdr->ip_sum = 0;
  iphdr->ip_sum = cksum(packet + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t));

  if (iphdr->ip_p == 1)
  {
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    icmp_hdr->icmp_sum = 0;
    icmp_hdr->icmp_sum = cksum(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t),
                               len - (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)));
  }

  return 1;
}

void forward_packet(struct sr_instance *sr, uint8_t *packet, struct sr_if *source_interface, struct sr_arpentry *arpentry, unsigned int len)
{
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)packet;

  if (sanity_check_packet(sr, packet, len, 1) == -1)
  {
    return;
  }

  memcpy(&ehdr->ether_shost, source_interface->addr, 6);
  memcpy(&ehdr->ether_dhost, arpentry->mac, 6);

  print_hdrs(packet, len);
  sr_send_packet(sr, packet, len, source_interface->name);
}

void create_icmp_packet(struct sr_instance *sr, int type, int code, char *interface_to_send_from, uint32_t new_dest_ip)
{

  unsigned int len = 0;
  uint8_t *packet = NULL;
  if (type == 3 && code == 3)
  {
    unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    uint8_t *packet = malloc(len * sizeof(uint8_t));

    sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    icmp_hdr->icmp_type = type;
    icmp_hdr->icmp_code = code;
    icmp_hdr->icmp_sum = 0;
    icmp_hdr->icmp_sum = cksum(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t),
                               len - (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)));
  }
  if (type == 11 && code == 0)
  {
    unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
    uint8_t *packet = malloc(len * sizeof(uint8_t));

    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    icmp_hdr->icmp_type = type;
    icmp_hdr->icmp_code = code;
    icmp_hdr->icmp_sum = 0;
    icmp_hdr->icmp_sum = cksum(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t),
                               len - (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)));
  }
  struct sr_if *interface = sr_get_interface(sr, interface_to_send_from);
  struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, new_dest_ip);

  sr_ethernet_hdr_t *eth = (sr_ethernet_hdr_t *)packet;
  memcpy(eth->ether_dhost, entry->mac, 6);
  memcpy(eth->ether_shost, interface->addr, 6);
  eth->ether_type = htons(ethertype_ip);

  sr_ip_hdr_t *iphdr = (struct sr_ip_hdr *)(sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  iphdr->ip_dst = new_dest_ip;
  iphdr->ip_src = interface->ip;
  iphdr->ip_id = 0;
  iphdr->ip_len = 56;
  iphdr->ip_off = 0;
  iphdr->ip_p = htons(ip_protocol_icmp);
  iphdr->ip_sum = 0;
  iphdr->ip_sum = cksum(packet + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t));
  /*   iphdr->ip_tos
 */
  iphdr->ip_ttl = 255;

  print_hdrs(packet, len);
  sr_send_packet(sr, packet, len, interface->name);
}

struct sr_if *sr_get_interface_with_ip(struct sr_instance *sr, uint32_t destination_ip)
{
  char *interfaces[3] = {"eth1", "eth2", "eth3"};
  int i = 0;
  for (i = 0; i < 3; i++)
  {
    struct sr_if *interface = sr_get_interface(sr, interfaces[i]);
    if (interface->ip == destination_ip)
    {
      return interface;
    }
  }

  return NULL;
}
void send_icmp_reply(struct sr_instance *sr, uint8_t *packet, uint32_t new_src, uint32_t new_dst, unsigned int len, char *interface)
{

  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)packet;
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  if (sanity_check_packet(sr, packet, len, 0) == -1)
  {
    return;
  }

  struct sr_if *current_interface = sr_get_interface(sr, interface);

  uint8_t orig_sender[6];
  memcpy(orig_sender, ehdr->ether_shost, 6);
  memcpy(&ehdr->ether_dhost, orig_sender, 6);
  memcpy(&ehdr->ether_shost, current_interface->addr, 6);

  iphdr->ip_dst = new_dst;
  iphdr->ip_src = new_src;
  iphdr->ip_ttl = 64;
  iphdr->ip_sum = 0;
  iphdr->ip_sum = cksum(packet + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t));
  icmp_hdr->icmp_type = 0;
  icmp_hdr->icmp_sum = 0;
  icmp_hdr->icmp_sum = cksum(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t),
                             len - (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)));
  print_hdrs(packet, len);
  sr_send_packet(sr, packet, len, interface);
}

void handle_arp_request(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *accepted_interface)
{
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)packet;
  uint8_t orig_sender[6];
  memcpy(orig_sender, ehdr->ether_shost, 6);
  memcpy(&ehdr->ether_dhost, orig_sender, 6);
  memcpy(&ehdr->ether_shost, accepted_interface->addr, 6);
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);

  /* Assemble ARP header */
  memcpy(&arp_hdr->ar_sha, accepted_interface->addr, 6);
  arp_hdr->ar_op = htons(arp_op_reply);
  memcpy(&arp_hdr->ar_tha, orig_sender, 6);
  uint32_t new_target_ip = arp_hdr->ar_sip;
  uint32_t new_source_ip = arp_hdr->ar_tip;
  arp_hdr->ar_tip = new_target_ip;
  arp_hdr->ar_sip = new_source_ip;
  sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);

  print_hdrs(packet, len);
  sr_send_packet(sr, packet, len, accepted_interface->name);
}

void handle_ip_packet(struct sr_instance *sr, uint8_t *packet, char *interface, unsigned int len)
{
  printf("This is an icmp packet\n");
  struct sr_if *current_interface = sr_get_interface(sr, interface);
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)packet;
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  uint32_t destination_ip = iphdr->ip_dst;
  struct sr_if *destination_interface;
  if ((destination_interface = sr_get_interface_with_ip(sr, destination_ip)) != NULL)
  /* If ip is destined for this interface, send back icmp reply */
  {
    printf("Icmp packet destination is our interface\n");
    if (iphdr->ip_p == 6 || iphdr->ip_p == 17)
    {
      /* Send port unreachable if tcp or udp packet*/
      create_icmp_packet(sr, 3, 3, interface, iphdr->ip_src);
    }

    send_icmp_reply(sr, packet, destination_interface->ip, iphdr->ip_src, len, interface);
    return;
  }
  else
  /* If ip not destined for our interface, see where it needs to go*/
  {
    printf("Icmp packet is not destined for our interface\n");
    struct sr_if *destination_interface = sr_get_interface_with_longest_match(sr, destination_ip);

    if (destination_interface == NULL)
    {
      /* Could not get match, send icmp unreachable*/
      printf("Could not get destination interface match\n");
      create_icmp_packet(sr, 3, 0, current_interface->name, iphdr->ip_src);
      return;
    }
    else
    {
      /* Match found, check arpcache to see if we have mac address */
      printf("Got destination interface longest match\n");

      struct sr_arpentry *arpentry = sr_arpcache_lookup(&sr->cache, destination_ip);

      if (arpentry != NULL)
      {
        /* Match found. Forward ip packet to next hop*/
        printf("Found arpentry for ip address\n");
        forward_packet(sr, packet, destination_interface, arpentry, len);
      }
      else
      {
        printf("Could not find arpentry for ip address\n");
        memcpy(&ehdr->ether_shost, destination_interface->addr, 6);

        struct sr_arpreq *request = sr_arpcache_queuereq(&sr->cache, destination_ip, packet, len, destination_interface->name);
        handle_arpreq(sr, request);
      }
    }
  }
}

void handle_arp_reply(struct sr_instance *sr, uint8_t *packet)
{
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  struct sr_arpreq *req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
  sr_arpcache_insert(&sr->cache, arp_hdr->ar_tha, arp_hdr->ar_tip);

  struct sr_packet *cur_packet = NULL;
  for (cur_packet = req->packets; cur_packet != NULL; cur_packet = cur_packet->next)
  {
    printf("############################################\n##########################################\nABOUT TO SEND PACKET\n############################################\n##########################################\n");
    sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)(cur_packet->buf);

    memcpy(&ehdr->ether_dhost, arp_hdr->ar_sha, 6);
    /*
    icmp_hdr->icmp_sum = 0;

    icmp_hdr->icmp_sum = cksum(cur_packet->buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t),
                               cur_packet->len - (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t))); */

    print_hdrs(cur_packet->buf, cur_packet->len);
    sr_send_packet(sr, cur_packet->buf, cur_packet->len, cur_packet->iface);
  }
  sr_arpreq_destroy(&sr->cache, req);
}

void sr_handlepacket(struct sr_instance *sr,
                     uint8_t *packet /* lent */,
                     unsigned int len,
                     char *interface /* lent */)
{

  printf("PRINTING RECEIVED PACKET\n");
  print_hdrs(packet, len);

  struct sr_if *current_interface = sr_get_interface(sr, interface);
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  uint16_t ethtype = ethertype(packet);

  /* If ARP packet */
  if (ethtype == ethertype_arp)
  {
    printf("Received an arp packet\n");
    if (arp_hdr->ar_op == ntohs(arp_op_request))
    {
      handle_arp_request(sr, packet, len, current_interface);
    }
    else
    {
      handle_arp_reply(sr, packet);
    }
    return;
  }
  else
  {
    handle_ip_packet(sr, packet, interface, len);
  }
}