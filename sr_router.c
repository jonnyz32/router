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

void sr_handlepacket(struct sr_instance *sr,
                     uint8_t *packet /* lent */,
                     unsigned int len,
                     char *interface /* lent */)
{
  /* REQUIRES */

  uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  assert(sr);
  assert(packet);
  assert(interface);

  /* Get the current interface*/
  /*   struct sr_if *current_interface = sr_get_interface(sr, interface);
 */

  /* Get iphdr and icmp_hdr*/
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)packet;

  /* Check if arp or icmp*/
  uint16_t ethtype = ethertype(packet);
  if (ethtype == ethertype_ip && sr_arpcache_lookup(&sr->cache, iphdr->ip_dst) != NULL)
  {
    /*Calculate checksum of request*/

    uint16_t request_iphdr_checksum_on_send = iphdr->ip_sum;
    uint16_t request_icmp_hdr_checksum_on_send = icmp_hdr->icmp_sum;

    iphdr->ip_sum = 0;
    icmp_hdr->icmp_sum = 0;

    uint16_t request_iphdr_checksum_on_receive = cksum(packet + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t));
    uint16_t request_icmp_hdr_checksum_on_receive = cksum(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t),
                                                          len - (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)));

    if (request_iphdr_checksum_on_receive != request_iphdr_checksum_on_send ||
        request_icmp_hdr_checksum_on_send != request_icmp_hdr_checksum_on_receive)
    {
      return;
    }

    /*Assemble ip header*/

    uint32_t new_src = iphdr->ip_dst;
    uint32_t new_dst = iphdr->ip_src;
    iphdr->ip_src = new_src;
    iphdr->ip_dst = new_dst;
    iphdr->ip_sum = 0;
    iphdr->ip_sum = cksum(packet + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t));

    /*Assemble icmp header*/
    icmp_hdr->icmp_type = 0;
    icmp_hdr->icmp_code = 0;
    icmp_hdr->icmp_sum = 0;
    icmp_hdr->icmp_sum = cksum(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t),
                               len - (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)));
  }
  /*   else if (ethtype == ethertype_arp)
 */
  else
  {

    /* Create new packet */

    if (ethtype == ethertype_ip)
    {

      /* Check if target ip is for our interface */
      uint32_t destination_address = arp_hdr->ar_tip;
      * /

          void get_matching_interface(struct sr_if * current_interface, )
              uint32_t first_3_bytes_target_ip = destination_address & 0xFFFFFF;
      char *interfaces[3] = {"eth1", "eth2", "eth3"};
      struct sr_if *current_interface;

      /* Get interface that we need to send request too*/
      int i;
      for (i = 0; i < 3; i++)
      {
        current_interface = sr_get_interface(sr, interfaces[i]);
        if ((current_interface->ip & 0xFFFFFF) == (first_3_bytes_target_ip))
        {
          break;
        }
      }
      uint8_t new_packet[sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)];
      sr_ethernet_hdr_t *new_eth = (sr_ethernet_hdr_t *)new_packet;
      sr_arp_hdr_t *new_arp = (sr_arp_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t));
      memcpy(new_eth->ether_dhost, broadcast, 6);
      memcpy(new_eth->ether_shost, broadcast, 6);
    }

    /* Get destination ip address */
    /*  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    uint32_t destination_address = arp_hdr->ar_tip; */

    /* Check if target ip IS ethernet ip*/
    if (destination_address == current_interface->ip)
    {
      /* Assemble ethernet header */
      sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)packet;
      uint8_t orig_sender[6];
      memcpy(orig_sender, ehdr->ether_shost, 6);
      memcpy(&ehdr->ether_dhost, orig_sender, 6);
      memcpy(&ehdr->ether_shost, current_interface->addr, 6);
      /*Send response back to mac address where we received the packet from */
      memcpy(&arp_hdr->ar_sha, current_interface->addr, 6);
      arp_hdr->ar_op = htons(arp_op_reply);
      memcpy(&arp_hdr->ar_tha, orig_sender, 6);
      uint32_t new_target_ip = arp_hdr->ar_sip;
      uint32_t new_source_ip = arp_hdr->ar_tip;
      arp_hdr->ar_tip = new_target_ip;
      arp_hdr->ar_sip = new_source_ip;
    }
    else
    {
      /* We need to send request from current interface to target ip address*/

      /*  if (target_ip in arpcache, then send reply back to sender){}
    else { */
      /* send request to broadcast from our interface */

      sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)packet;
      memcpy(&ehdr->ether_dhost, broadcast, 6);
      memcpy(&ehdr->ether_shost, current_interface->addr, 6);
      /*Send response back to mac address where we received the packet from */
      memcpy(&arp_hdr->ar_sha, current_interface->addr, 6);
      arp_hdr->ar_op = htons(arp_op_request);
      memcpy(&arp_hdr->ar_tha, "000000", 6);
      arp_hdr->ar_tip = destination_address;
      arp_hdr->ar_sip = current_interface->ip;
    }
  }

  /* Checks if an IP->MAC mapping is in the cache. IP is in network byte order. 
   You must free the returned structure if it is not NULL. */
  /*     sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
 */
  /*     struct sr_arpentry *arpentry = sr_arpcache_lookup(&sr->cache, arp_hdr->ar_tip); */
  /* sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
    sr_arpcache_insert(&sr->cache, arp_hdr->ar_tha, arp_hdr->ar_tip); 
 */

  sr_send_packet(sr, packet, len, interface);

  printf("*** -> Received packet of length %d \n", len);
  printf("packet: %x\n", *packet);
  printf("interface: %s\n", interface);
  print_hdrs(packet, len);
} /* end sr_ForwardPacket */

struct sr_if *sr_get_interface_with_ip(struct sr_instance *sr, uint32_t destination_ip)
{
  char *interfaces[3] = [ "eth1", "eth2", "eth3" ];
  int i = 0;
  for (i = 0; i < 3; i++)
  {
    struct sr_if *interface = sr_get_interface(sr, interface);
    if (interface->ip == destination_ip)
    {
      return interface;
    }
  }

  return NULL;
}

struct sr_if *sr_get_interface_with_longest_match(struct sr_instance *sr, uint32_t destination_ip)
{

  uint32_t first_3_bytes_target_ip = destination_address & 0xFFFFFF;
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

  void sr_handlepacket(struct sr_instance * sr,
                       uint8_t * packet /* lent */,
                       unsigned int len,
                       char *interface /* lent */)
  {

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
      sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

      /* Assemble ARP header */
      memcpy(&arp_hdr->ar_sha, current_interface->addr, 6);
      arp_hdr->ar_op = htons(arp_op_reply);
      memcpy(&arp_hdr->ar_tha, orig_sender, 6);
      uint32_t new_target_ip = arp_hdr->ar_sip;
      uint32_t new_source_ip = arp_hdr->ar_tip;
      arp_hdr->ar_tip = new_target_ip;
      arp_hdr->ar_sip = new_source_ip;
      sr_send_packet(sr, packet, len, interface);
      return;
    }
    else
    {

      /*Assemble icmp header*/
      sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
      icmp_hdr->icmp_type = 0;
      icmp_hdr->icmp_code = 0;
      icmp_hdr->icmp_sum = 0;
      icmp_hdr->icmp_sum = cksum(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t),
                                 len - (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)));

      /* ethtype is ip_packet*/
      sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
      uint32_t destination_ip = iphdr->ip_dst;
      struct sr_if *interface;
      if ((interface = sr_get_interface_with_ip(sr, destination_ip)) != NULL)
      /* If ip is destined for this interface, send back icmp reply */
      {
        iphdr->ip_dst = iphdr->ip_src;
        iphdr->ip_src = interface->ip;
        iphdr->ip_ttl -= 1;
        iphdr->ip_sum = 0;
        iphdr->ip_sum = cksum(packet + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t));

        sr_send_packet(sr, packet, len, interface);
        return;
      }
      else
      /* If ip not destined for our interface, see where it needs to go*/
      {
        struct sr_if *interface = sr_get_interface_with_longest_match(sr, destination_ip);

        if (interface == NULL)
        {
          /* Could not get match, send icmp unreachable*/
        }
        else
        {
          /* Match found, check arpcache to see if we have mac address */

          if ((struct sr_arpentry *arpentry = arp_entrysr_arpcache_lookup(&sr->cache, destination_ip)) != NULL)
          {
            /* Match found. Forward ip packet to next hop*/

            memcpy(&ehdr->ether_dhost, arpentry->mac, 6);
            memcpy(&ehdr->ether_shost, current_interface->addr, 6);

            iphdr->ip_dst = arpentry->ip;
            iphdr->ip_src = interface->ip;
            iphdr->ip_ttl -= 1;
            iphdr->ip_sum = 0;
            iphdr->ip_sum = cksum(packet + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t));
          }
          else
          {
            /* No arpentry in cache, create new arp packet and send it as broadcast*/
            uint8_t new_packet[sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)];
            sr_ethernet_hdr_t *new_eth = (sr_ethernet_hdr_t *)new_packet;
            sr_arp_hdr_t *new_arp = (sr_arp_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t));
            memcpy(new_eth->ether_dhost, broadcast, 6);
            memcpy(new_eth->ether_shost, interface->addr, 6);


            

             memcpy(&new_arp->ar_sha, current_interface->addr, 6);
            arp_hdr->ar_op = htons(arp_op_request);
            memcpy(&arp_hdr->ar_tha, {}, 6);
      uint32_t new_target_ip = arp_hdr->ar_sip;
      uint32_t new_source_ip = arp_hdr->ar_tip;
      arp_hdr->ar_tip = new_target_ip;
      arp_hdr->ar_sip = new_source_ip;
      sr_send_packet(sr, packet, len, interface);
          }
        }
      }
    }
  }