
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>

static const char internal_if[] = "eth1";

int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */

assert(nat);

  /* Acquire mutex lock */
pthread_mutexattr_init(&(nat->attr));
pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

pthread_attr_init(&(nat->thread_attr));
pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

nat->mappings = NULL;
  /* Initialize any variables here */


nat->nextIcmpIdentNumber = STARTING_PORT_NUMBER;
nat->nextTcpPortNumber = STARTING_PORT_NUMBER;

return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */

while (nat->mappings)
{
  sr_nat_destroy_mapping(nat, nat->mappings);
}

pthread_kill(nat->thread, SIGKILL);
return pthread_mutex_destroy(&(nat->lock)) &&
pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
struct sr_nat *nat = (struct sr_nat *)nat_ptr;
while (1) {
  sleep(1.0);
  pthread_mutex_lock(&(nat->lock));

  time_t curtime = time(NULL);

    /* handle periodic tasks here */

  sr_nat_mapping_t *mappingWalker = nat->mappings;

  while(mappingWalker)
  {

/*************** If it is an ICMP packet******************/
   if (mappingWalker->type == nat_mapping_icmp)
   {
    if (difftime(curtime, mappingWalker->last_updated) > nat->icmpTimeout)
    {
     sr_nat_mapping_t* next = mappingWalker->next;

/***************Print out information of the destroyed mapping***************************************/
              /* fprintf(stderr, "ICMP mapping %u.%u.%u.%u:%u <-> %u timed out.\n",
                  (ntohl(mappingWalker->ip_int) >> 24) & 0xFF,
                  (ntohl(mappingWalker->ip_int) >> 16) & 0xFF,
                  (ntohl(mappingWalker->ip_int) >> 8) & 0xFF,
                  ntohl(mappingWalker->ip_int) & 0xFF,
                  ntohs(mappingWalker->aux_int), ntohs(mappingWalker->aux_ext));*/

                  sr_nat_destroy_mapping(nat, mappingWalker);
                  mappingWalker = next;
                }
                else
                {
                 mappingWalker = mappingWalker->next;
               }
             }

/*************** If it is an TCP packet******************/
             else if (mappingWalker->type == nat_mapping_tcp)
             {
               
             }

           }      
           pthread_mutex_unlock(&(nat->lock));
         }
         return NULL;
       }

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
       struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
        uint16_t aux_ext, sr_nat_mapping_type type ) {

         pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
         struct sr_nat_mapping * copy = NULL, * result = NULL;

/*************Search for mapping ******************/

         for (sr_nat_mapping_t * mappingWalker = nat->mappings; mappingWalker != NULL; mappingWalker = mappingWalker->next)
         {
           if ((mappingWalker->type == type) && (mappingWalker->aux_ext == aux_ext))
           {
             result = mappingWalker;
             break;
           }
         }
         
         if (result)
         {
          result->last_updated = time(null);
          copy = malloc(sizeof (struct sr_nat_mapping));
          assert(copy);
          memcpy(copy, result, sizeof (struct sr_nat_mapping))
        }

        pthread_mutex_unlock(&(nat->lock));
        return copy;
      }

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
      struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
        uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

        pthread_mutex_lock(&(nat->lock));

 /* handle lookup here, malloc and assign to copy */
        struct sr_nat_mapping * copy = NULL, * result = NULL;

/*************Search for mapping ******************/

        for (sr_nat_mapping_t * mappingWalker = nat->mappings; mappingWalker != NULL; mappingWalker = mappingWalker->next)
        {
          if ((mappingWalker->type == type) && (mappingWalker->aux_int == aux_int)&& (mappingWalker->ip_int == ip_int))
          {
            result = mappingWalker;
            break;
          }
        }

        if (result)
        {
          result->last_updated = time(null);
          copy = malloc(sizeof (struct sr_nat_mapping));
          assert(copy);
          memcpy(copy, result, sizeof (struct sr_nat_mapping))
        }

        pthread_mutex_unlock(&(nat->lock));
        return copy;
      }

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
   struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
    uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

    pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
    struct sr_nat_mapping *mapping = NULL;
    mapping = malloc(sizeof(sr_nat_mapping_t);
     
      mapping->conns = NULL;
      mapping->aux_ext = natNextMappingNumber(nat,type);

      mapping->ip_int = ip_int;
      mapping->aux_int = aux_int;
      mapping->type = type;
      mapping->last_updated = time(NULL);

      if (type == nat_mapping_icmp)
      {
        printf("%sCreated new ICMP mapping\n", );
        
      }
      else if (type == nat_mapping_tcp)
      {
        printf("%sCreated new TCP mapping\n", );
        
      }

  /* Add mapping to the front of the list. */
      mapping->next = nat->mappings;
      nat->mappings = mapping;

      copy = malloc(sizeof(sr_nat_mapping_t);;
        memcpy(copy, mapping, sizeof(sr_nat_mapping_t));
        pthread_mutex_unlock(&(nat->lock));
        return copy;
      }


      void NatHandleRecievedIpPacket(sr_instance_t* sr, sr_ip_hdr_t* ipPacket, unsigned int length,
       sr_if_t const * const receivedInterface)
      {
       if (ipPacket->ip_p == ip_protocol_tcp)
       {
        natHandleTcpPacket(sr, ipPacket, length, receivedInterface);
      }
      else if (ipPacket->ip_p == ip_protocol_icmp)
      {
        natHandleIcmpPacket(sr, ipPacket, length, receivedInterface);
      }
      else
      {
        fprintf(stderr, "%sReceived packet of unknown IP protocol type %u. Dropping.\n", ipPacket->ip_p);
      }
    }


/**
 * natHandleIcmpPacket()\n
 * @brief Function processes an ICMP packet when NAT functionality is enabled. 
 * @param sr pointer to simple router structure.
 * @param ipPacket pointer to received IP datagram with an ICMP payload.
 * @param length length of the IP datagram
 * @param receivedInterface interface on which this packet was originally received.
 */
 static void natHandleIcmpPacket(sr_instance_t* sr, sr_ip_hdr_t* ipPacket, unsigned int length, sr_if_t const * const receivedInterface)
 {
  
  uint32_t ip_dst = ipPacket->ip_dsr;
  sr_icmp_hdr_t * icmpHeader = icmp_header(ipPacket);

  if (!icmp_validpacket(ipPacket));
  {
    printf("Received ICMP packet with wrong checksum. Dropping.\n");
    return;
  }

  if ((sr_get_interface(sr,internalInterfaceName)->ip == receivedInterface->ip) &&(sr_packet_is_for_me(sr, ip_dst)))
  {
 /***************************packet is for me and it's from inside*****************************************/
    IpHandleReceivedPacketToUs(sr, ipPacket, length, receivedInterface);
  }
  else if (sr_get_interface(sr,internal_if)->ip == receivedInterface->ip)
  {
/**************************************outbound packet**********************************/
    if ((icmpHeader->icmp_type == icmp_type_echo_request)||(icmpHeader->icmp_type == icmp_type_echo_reply))
    {
     sr_icmp_hdr_t * icmpPingHdr = (sr_icmp_hdr_t *) icmpHeader;
     sr_nat_mapping_t * natLookupResult = sr_nat_lookup_internal(sr->nat, ipPacket->ip_src,icmpPingHdr->ident, nat_mapping_icmp);
     
     /* No mapping? Make one! */
     if (natLookupResult == NULL)
     {
       natLookupResult = sr_nat_insert_mapping(sr->nat, ipPacket->ip_src, icmpPingHdr->ident, nat_mapping_icmp);
     }
     natHandleReceivedOutboundIpPacket(sr, ipPacket, length, receivedInterface, natLookupResult);
     free(natLookupResult);
    }
   else 
   {
     sr_ip_hdr_t * embeddedIpPacket = NULL;
     sr_nat_mapping_t * natLookupResult = NULL;
     
     if ((icmpHeader->icmp_type == icmp_type_desination_unreachable)||(icmpHeader->icmp_type == icmp_type_time_exceeded))
     {
      sr_icmp_t3_hdr_t * unreachableHeader = (sr_icmp_t3_hdr_t *) icmpHeader;
      embeddedIpPacket = (sr_ip_hdr_t *) unreachableHeader->data;
     }
     else
     {
            /* By RFC, no other ICMP types have to support NAT traversal (SHOULDs 
             * instead of MUSTs). It's not that I'm lazy, it's just that this 
             * assignment is hard enough as it is. */
     fprintf(stderr, "\tDropping unsupported outbound ICMP packet Type: %d\n", icmpHeader->icmp_type);
     fprintf(stderr, "\tCode: %d\n", icmpHeader->icmp_code));
     return;
     }
    assert(embeddedIpPacket);

    if (embeddedIpPacket->ip_p == ip_protocol_icmp)
    {
     sr_icmp_t0_hdr_t * embeddedIcmpHeader = icmp_header(embeddedIpPacket);
     if ((embeddedIcmpHeader->icmp_type == icmp_type_echo_request)||(embeddedIcmpHeader->icmp_type == icmp_type_echo_reply))
      {
       natLookupResult = sr_nat_lookup_internal(sr->nat, embeddedIpPacket->ip_dst,embeddedIcmpHeader->ident, nat_mapping_icmp);
      }
            /* Otherwise, we will not have a mapping for this ICMP type. 
             * Either way, echo request and echo reply are the only ICMP 
             * packet types that can generate another ICMP packet. */ 
    }
   else if(embeddedIpPacket->ip_p == ip_protocol_tcp)
   {
    sr_tcp_hdr_t * embeddedTcpHeader = tcp_header(embeddedIpPacket);
    natLookupResult = sr_nat_lookup_internal(sr->nat, embeddedIpPacket->ip_dst,embeddedTcpHeader->destinationPort, nat_mapping_tcp);
   }
   else
   {
    return;
    }
/************if hit the entry for that packet, modify and send it out************/
  if (natLookupResult != NULL)
     {
       natHandleReceivedOutboundIpPacket(sr, ipPacket, length, receivedInterface, natLookupResult); 
       free(natLookupResult);
     }
   }
 }
 else{

/***************************************Inbound packet*************************************/
 if (!sr_packet_is_for_me(sr, ip_dst))
/**packet no for me**/
struct sr_rt* lpmatch = longest_prefix_matching(sr, ipPacket->ip_dst);

  { if (sr_get_interface(sr,internal_if)->ip != sr_get_interface(sr, lpmatch->interface)->ip)
  {
            /* Sender not attempting to traverse the NAT. Allow the packet to be routed without alteration. */
            /* Just simply forward that packet*/
       struct sr_if* s_interface = sr_get_interface(sr, longest_prefix_matching(sr,ipPacket->ip_dst)->interface);
           
        /* Check ARP cache */
         struct sr_arpentry * arp_entry = sr_arpcache_lookup(&sr->cache, lpmatch->gw.s_addr);

        if (arp_entry == 0){

            /* If miss APR cache, add the packet to ARP request queue */
            req = sr_arpcache_queuereq(&sr->cache, lpmatch->gw.s_addr, ip_pkt, 
                                      len, s_interface->name);
            sr_handle_arpreq(sr, req);
        } else {

            /* Hit ARP cache, send out the packet right away using next-hop */
            /* Encap the ARP request into ethernet frame and then send it */
            sr_ethernet_hdr_t sr_ether_pkt;

            memcpy(sr_ether_pkt.ether_dhost, arp_entry->mac, ETHER_ADDR_LEN); /* Address from routing table */
            memcpy(sr_ether_pkt.ether_shost, s_interface->addr, ETHER_ADDR_LEN); /* Hardware address of the outgoing interface */
            sr_ether_pkt.ether_type = htons(ethertype_ip);

            uint8_t *packet_rqt;
            unsigned int total_len = len + sizeof(struct sr_ethernet_hdr);
            packet_rqt = malloc(total_len);
            memcpy(packet_rqt, &(sr_ether_pkt), sizeof(sr_ether_pkt));
            memcpy(packet_rqt + sizeof(sr_ether_pkt), ip_pkt, len);

            /* Forward the IP packet*/
            sr_send_packet(sr, packet_rqt, total_len, s_interface->name);
            free(packet_rqt);
          }
        }

   }
}

/**
 * natHandleTcpPacket()\n
 * @brief Function processes a TCP packet when NAT functionality is enabled. 
 * @param sr pointer to simple router structure.
 * @param ipPacket pointer to received IP datagram with a TCP payload.
 * @param length length of the IP datagram
 * @param receivedInterface interface on which this packet was originally received.
 */

 static void natHandleTcpPacket(sr_instance_t* sr, sr_ip_hdr_t* ipPacket, unsigned int length, sr_if_t const * const receivedInterface)
 {

 }

/**
 * sr_nat_destroy_mapping()\n
 * @brief removes a mapping from the linked list. Based off of ARP cache implementation.
 * @param nat pointer to NAT structure.
 * @param natMapping mapping to remove from list.
 * @warning Assumes that NAT structure is already locked!
*/
 static void sr_nat_destroy_mapping(sr_nat_t* nat, sr_nat_mapping_t* natMapping)
 {
   if (natMapping)
   {
    sr_nat_mapping_t *req, *prev = NULL, *next = NULL;

/* move out all the natMapping we want to destroy and reconnect the mapping list */


    for (req = nat->mappings; req != NULL; req = req->next)
    {
     if (req == natMapping)
     {
      if (prev)
      {
       next = req->next;
       prev->next = next;
     }
     else
     {
       next = req->next;
       nat->mappings = next;
     }
     
     break;
   }
   prev = req;
 }
 
 while (natMapping->conns != NULL)
 {
   sr_nat_connection_t * curr = natMapping->conns;
   natMapping->conns = curr->next;
   
   free(curr);
 }
 
 free(natMapping);
}
}

 /*
 *-----------------------------------------------------------------------------
 * Private Function Definitions
 *-----------------------------------------------------------------------------
 */

 static uint16_t natNextMappingNumber(sr_nat_t* nat, sr_nat_mapping_type mappingType)
 {
   uint16_t startIndex;
   sr_nat_mapping_t * mappingIterator = nat->mappings;
   if (mappingType == nat_mapping_icmp)
   {
    startIndex = nat->nextIcmpIdentNumber;
  }
  else if (mappingType == nat_mapping_tcp)
  {
    startIndex = nat->nextTcpPortNumber;
  }
  
   /* Look to see if a mapping already exists for this port number */
  while (mappingIterator)
  {
    if ((mappingIterator->type == mappingType) && (htons(startIndex) == mappingIterator->aux_ext))
    {
         /* Mapping already exists for this value. Go to the next one and start the search over. */
     startIndex = (startIndex == LAST_PORT_NUMBER) ? STARTING_PORT_NUMBER : (startIndex + 1);
     mappingIterator = nat->mappings;
   }
   else
   {
     mappingIterator = mappingIterator->next;
   }
 }
 
   /* Setup the next search start location for the next mapping */
 if (mappingType == nat_mapping_icmp)
 {
  nat->nextIcmpIdentNumber = (startIndex == LAST_PORT_NUMBER) ? STARTING_PORT_NUMBER : (startIndex + 1);
}
else if (mappingType == nat_mapping_tcp)
{
  nat->nextTcpPortNumber = (startIndex == LAST_PORT_NUMBER) ? STARTING_PORT_NUMBER : (startIndex + 1);
}

return startIndex;
}


