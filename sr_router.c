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
#include <string.h>
#include <stdlib.h>

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

uint8_t *create_icmp_packet(struct sr_instance *sr, int type, int code, struct sr_if *interface, uint32_t org_src_ip)
{
  if (type == 11 && code == 0)
  {
    /* This is time to live exceeded packet*/
    uint8_t *packet = malloc(70 * sizeof(uint8_t));
    struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, org_src_ip);

    sr_ethernet_hdr_t *eth = (sr_ethernet_hdr_t *)packet;
    memcpy(eth->ether_dhost, entry->mac, 6);
    memcpy(eth->ether_shost, interface->addr, 6);
    eth->ether_type = htons(ethertype_ip);

    sr_ip_hdr_t *iphdr = (struct sr_ip_hdr *)(sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    iphdr->ip_dst = org_src_ip;
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

    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    icmp_hdr->icmp_type = type;
    icmp_hdr->icmp_code = code;
    icmp_hdr->icmp_sum = 0;
    icmp_hdr->icmp_sum = cksum(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t),
                               70 - (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)));

    return packet;
  }
}

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
    uint32_t gateway_ip = entry->gw.s_addr;
    uint32_t mask = entry->mask.s_addr;
    uint32_t network_ip = gateway_ip & mask;

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

#if 0
struct sr_if *sr_get_interface_with_longest_match(struct sr_instance *sr, uint32_t destination_ip)
{
  /* sr->routing_table->dest;
  sr->routing_table->mask; */
  uint32_t first_3_bytes_target_ip = destination_ip & 0xFFFFFF;
  char *interfaces[3] = {"eth1", "eth2", "eth3"};
  struct sr_if *current_interface;

  /* Get interface that we need to send request too*/
  int i;
  for (i = 0; i < 3; i++)
  {
    current_interface = sr_get_interface(sr, interfaces[i]);
    if ((current_interface->ip & 0xFFFFFF) == (first_3_bytes_target_ip))
    {
      return current_interface;
    }
  }
  return NULL;
}
#endif

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

void sr_handlepacket(struct sr_instance *sr,
                     uint8_t *packet /* lent */,
                     unsigned int len,
                     char *interface /* lent */)

{

  printf("PRINTING RECEIVED PACKET\n");
  print_hdrs(packet, len);

  struct sr_if *current_interface = sr_get_interface(sr, interface);
  /* Assemble ethernet header */
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)packet;
  uint8_t orig_sender[6];
  memcpy(orig_sender, ehdr->ether_shost, 6);
  memcpy(&ehdr->ether_dhost, orig_sender, 6);
  memcpy(&ehdr->ether_shost, current_interface->addr, 6);

  uint16_t ethtype = ethertype(packet);

  /* If ARP packet */
  if (ethtype == ethertype_arp)
  {
    printf("This is an arp packet\n");

    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    if (arp_hdr->ar_op == ntohs(arp_op_request))
    {
      /* If arp request */
      sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);

      /* Assemble ARP header */
      memcpy(&arp_hdr->ar_sha, current_interface->addr, 6);
      arp_hdr->ar_op = htons(arp_op_reply);
      memcpy(&arp_hdr->ar_tha, orig_sender, 6);
      uint32_t new_target_ip = arp_hdr->ar_sip;
      uint32_t new_source_ip = arp_hdr->ar_tip;
      arp_hdr->ar_tip = new_target_ip;
      arp_hdr->ar_sip = new_source_ip;
      print_hdrs(packet, len);

      sr_send_packet(sr, packet, len, interface);
    }
    else
    {
      /* This is reply, just cache*/

      struct sr_arpreq *req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
      struct sr_packet *packet = NULL;

      for (packet = req->packets; packet != NULL; packet = packet->next)
      {
        printf("############################################\n##########################################\nABOUT TO SEND PACKET\n############################################\n##########################################\n");
        print_hdrs(packet->buf, packet->len);
        sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)packet->buf;
        memcpy(&ehdr->ether_dhost, arp_hdr->ar_sha, 6);

        sr_send_packet(sr, packet->buf, packet->len, packet->iface);
      }
      sr_arpreq_destroy(&sr->cache, req);
    }

    return;
  }
  else
  {
    printf("This is an icmp packet\n");

    /*Assemble icmp header*/
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    if (iphdr->ip_p == 6 || iphdr->ip_p == 17)
    {
      /* This is tcp/udp, send port unreachable */
      iphdr->ip_dst = iphdr->ip_src;
      iphdr->ip_src = current_interface->ip;

      icmp_hdr->icmp_type = 3;
      icmp_hdr->icmp_code = 3;
      sr_send_packet(sr, packet, len, interface);
      return;
    }

    /*     icmp_hdr->icmp_type = 0;
 */
    icmp_hdr->icmp_code = 0;
    icmp_hdr->icmp_sum = 0;
    icmp_hdr->icmp_sum = cksum(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t),
                               len - (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)));

    /* ethtype is ip_packet*/
    uint32_t destination_ip = iphdr->ip_dst;
    struct sr_if *destination_interface;
    if ((destination_interface = sr_get_interface_with_ip(sr, destination_ip)) != NULL)
    /* If ip is destined for this interface, send back icmp reply */
    {
      printf("Icmp packet is destination is our interface\n");
      iphdr->ip_dst = iphdr->ip_src;
      iphdr->ip_src = destination_interface->ip;
      iphdr->ip_ttl -= 1;
      iphdr->ip_sum = 0;
      iphdr->ip_sum = cksum(packet + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t));
      print_hdrs(packet, len);
      sr_send_packet(sr, packet, len, interface);
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
        /* Eth header is already set to send to source host*/

        iphdr->ip_dst = iphdr->ip_src;
        iphdr->ip_src = current_interface->ip;
        icmp_hdr->icmp_type = 3;
        icmp_hdr->icmp_code = 0;
        print_hdrs(packet, len);
        sr_send_packet(sr, packet, len, interface);

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

          memcpy(&ehdr->ether_shost, destination_interface->addr, 6);

          memcpy(&ehdr->ether_dhost, arpentry->mac, 6);
          /*           memcpy(&ehdr->ether_shost, destination_interface->addr, 6);
 */
          /*           iphdr->ip_dst = arpentry->ip;
 */
          /*           iphdr->ip_src = destination_interface->ip;
 */
          iphdr->ip_ttl -= 1;
          iphdr->ip_sum = 0;
          iphdr->ip_sum = cksum(packet + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t));
          print_hdrs(packet, len);

          /* Check if ttl is 0, and if yes, then send time exceeded*/
          if (iphdr->ip_ttl < 1)
          {
            printf("###########################################3\nTIME TO LIVE IS 0\n######################################\n");
            printf("Sending time exceeded\n");
            uint8_t *new_packet = create_icmp_packet(sr, 11, 0, current_interface, iphdr->ip_src);

            print_hdrs(new_packet, len);
            sr_send_packet(sr, new_packet, 70, current_interface->name);
            free(new_packet);
            return;
          }

          sr_send_packet(sr, packet, len, destination_interface->name);
        }
        else
        {
          printf("Could not find arpentry for ip address\n");
          memcpy(&ehdr->ether_shost, destination_interface->addr, 6);

          struct sr_arpreq *request = sr_arpcache_queuereq(&sr->cache, destination_ip, packet, len, destination_interface->name);
          handle_arpreq(sr, request);

/* No arpentry in cache, create new arp packet and send it as broadcast*/
#if 0
          uint8_t new_packet[42];
          sr_ethernet_hdr_t *new_eth = (sr_ethernet_hdr_t *)new_packet;
          sr_arp_hdr_t *new_arp = (sr_arp_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t));
          memcpy(new_eth->ether_dhost, broadcast_eth, 6);
          memcpy(new_eth->ether_shost, destination_interface->addr, 6);
          new_eth->ether_type = htons(ethertype_arp);

          memcpy(&new_arp->ar_sha, destination_interface->addr, 6);
          new_arp->ar_op = htons(arp_op_request);
          memcpy(&new_arp->ar_tha, broadcast_arp, 6);
          new_arp->ar_tip = destination_ip;
          new_arp->ar_sip = destination_interface->ip;
          new_arp->ar_hrd = htons(0x0001); /* format of hardware address   */
          new_arp->ar_pro = htons(0x0800); /* format of protocol address   */
          new_arp->ar_hln = 6;             /* length of hardware address   */
          new_arp->ar_pln = 4;             /* length of protocol address   */
          print_hdrs(new_packet, 42);
          sr_send_packet(sr, new_packet, 42, destination_interface->name);
#endif
        }
      }
    }
  }
}
