
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>

#include "sr_nat.h"
#include "sr_protocol.h"
#include "sr_router.h"
#include "sr_utils.h"

static const char internal_if[] = "eth1";

static sr_nat_connection_t *sr_nat_lookup_connection(sr_nat_mapping_t *natEntry, uint32_t ip_ext, 
                                                    uint16_t port_ext);
static void natHandleIcmpPacket(sr_instance_t* sr, sr_ip_hdr_t *ipPacket, unsigned int length,
                               sr_if_t const *const r_interface);
static void natHandleTcpPacket(sr_instance_t *sr, sr_ip_hdr_t *ipPacket, unsigned int length,
                              sr_if_t const *const r_interface);
static void natHandleReceivedOutboundIpPacket(struct sr_instance *sr, sr_ip_hdr_t *packet, unsigned int length,
                                             const struct sr_if *const r_interface, sr_nat_mapping_t *natMapping);
static void natHandleReceivedInboundIpPacket(struct sr_instance *sr, sr_ip_hdr_t *packet, unsigned int length,
                                            const struct sr_if *const r_interface, sr_nat_mapping_t *natMapping);
static void natRecalculateTcpChecksum(sr_ip_hdr_t *tcpPacket, unsigned int length);
static void sr_nat_destroy_connection(sr_nat_mapping_t *natMapping, sr_nat_connection_t *connection);
static void sr_nat_destroy_mapping(sr_nat_t *nat, sr_nat_mapping_t *natMapping);
static uint16_t natNextMappingNumber(sr_nat_t *nat, sr_nat_mapping_type mappingType);

int sr_nat_init(struct sr_nat *nat) 
{ 

    /* Initializes the nat */
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
    nat->nextIcmpIdentNumber = STARTING_PORT_NUMBER;
    nat->nextTcpPortNumber = STARTING_PORT_NUMBER;

    return success;
}

int sr_nat_destroy(struct sr_nat *nat) 
{  

    /* Destroys the nat (free memory) */
    pthread_mutex_lock(&(nat->lock));

    while (nat->mappings)
    {
      sr_nat_destroy_mapping(nat, nat->mappings);
    }

    pthread_kill(nat->thread, SIGKILL);

    return pthread_mutex_destroy(&(nat->lock)) &&
           pthread_mutexattr_destroy(&(nat->attr));
}

void *sr_nat_timeout(void *nat_ptr) 
{  

    /* Periodic Timeout handling */
    struct sr_nat *nat = (struct sr_nat *)nat_ptr;

    while (1) 
    {
      sleep(1.0);
      pthread_mutex_lock(&(nat->lock));

      time_t curtime = time(NULL);
      sr_nat_mapping_t *mappingWalker = nat->mappings;

      while(mappingWalker)
      {

        /* If it is an ICMP packet */
        if (mappingWalker->type == nat_mapping_icmp)
        {
          if (difftime(curtime, mappingWalker->last_updated) > nat->icmpTimeout)
          {
            sr_nat_mapping_t *next = mappingWalker->next;

            /* Print out information of the destroyed mapping */
            sr_nat_destroy_mapping(nat, mappingWalker);
            mappingWalker = next;
          } else {
              mappingWalker = mappingWalker->next;
            }
        } else if (mappingWalker->type == nat_mapping_tcp) {

            /* If it is an TCP packet */
          	sr_nat_connection_t * conn_walker = mappingWalker->conns;

          	while(onnectionIterator)
          	{
          	  if ((conn_walker->connectionState == nat_conn_connected)
                  && (difftime(curtime, conn_walker->lastAccessed)
                  > nat->tcpEstablishedTimeout))
          	  {
                sr_nat_connection_t *next = conn_walker->next;
          	    sr_nat_destroy_connection(mappingWalker, conn_walker);
          	    conn_walker = next;
          	  } else if (((conn_walker->connectionState == nat_conn_outbound_syn)
                         || (conn_walker->connectionState == nat_conn_time_wait))
                         && (difftime(curtime, conn_walker->lastAccessed)
                         > nat->tcpTransitoryTimeout))
                { 
                  sr_nat_connection_t *next = conn_walker->next;                  
                  sr_nat_destroy_connection(mappingWalker, conn_walker);
                  conn_walker = next;
                } else if ((conn_walker->connectionState == nat_conn_inbound_syn_pending)
                           && (difftime(curtime, conn_walker->lastAccessed)
                           > nat->tcpTransitoryTimeout))
                  { sr_nat_connection_t *next = conn_walker->next;

                    if (conn_walker->queuedInboundSyn) {
                  		struct sr_rt *lpmatch = longest_prefix_matching(nat->routerState,
                                                                     ((conn_walker->queuedInboundSyn)->ip_src))
                  		sr_icmp_with_payload(nat->routerState, conn_walker->queuedInboundSyn, lpmatch->interface, 3, 3);
                    }
                    sr_nat_destroy_connection(mappingWalker, conn_walker);
                    conn_walker = next;
          		    } else {
                      conn_walker = conn_walker->next;
                    }
            }
          	if (mappingWalker->conns == NULL) {
              sr_nat_mapping_t *next = mappingWalker->next;

              sr_nat_destroy_mapping(nat, mappingWalker);
              mappingWalker = next;
            } else {
                mappingWalker = mappingWalker->next;
              }
          } else {
              mappingWalker = mappingWalker->next;
            }
      }

      pthread_mutex_unlock(&(nat->lock));
    }

    return NULL;
}


/* Get the mapping associated with given external port
Must free the returned structure if it is not NULL */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
                                             uint16_t aux_ext,
                                             sr_nat_mapping_type type)
{
    pthread_mutex_lock(&nat->lock);

    /* Handle lookup , malloc and assign to copy */
    struct sr_nat_mapping *copy = NULL, *result = NULL;

    /* Search for mapping */
    for (sr_nat_mapping_t *mappingWalker = nat->mappings; mappingWalker != NULL; mappingWalker = mappingWalker->next)
    {
      if ((mappingWalker->type == type) && (mappingWalker->aux_ext == aux_ext))
      {
        result = mappingWalker;
        break;
      }
    }

    if (result)
    {
      result->last_updated = time(NULL);
      copy = malloc(sizeof(struct sr_nat_mapping));
      assert(copy);
      memcpy(copy, result, sizeof(struct sr_nat_mapping));
    }

    pthread_mutex_unlock(&(nat->lock));
    return copy;
}

/* Get the mapping associated with given internal (ip, port) pair
Must free the returned structure if it is not NULL */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
                                             uint32_t ip_int,
                                             uint16_t aux_int,
                                             sr_nat_mapping_type type)
{
    pthread_mutex_lock(&nat->lock);

    /* Handle lookup, malloc and assign to copy */
    struct sr_nat_mapping *copy = NULL, *result = NULL;

    /* Search for mapping */

    for (sr_nat_mapping_t *mappingWalker = nat->mappings; mappingWalker != NULL; mappingWalker = mappingWalker->next)
    {
      if ((mappingWalker->type == type) && (mappingWalker->aux_int == aux_int)&& (mappingWalker->ip_int == ip_int))
      {
        result = mappingWalker;
        break;
      }
    }

    if (result)
    {
      result->last_updated = time(NULL);
      copy = malloc(sizeof(struct sr_nat_mapping));
      assert(copy);
      memcpy(copy, result, sizeof(struct sr_nat_mapping));
    }

    pthread_mutex_unlock(&(nat->lock));
    return copy;
}

/* Insert a new mapping into the nat's mapping table
Actually returns a copy to the new mapping, for thread safety */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
                                            uint32_t ip_int,
                                            uint16_t aux_int,
                                            sr_nat_mapping_type type)
{
    pthread_mutex_lock(&nat->lock);

    /* Handle insert here, create a mapping, and then return a copy of it */
    struct sr_nat_mapping *mapping = NULL;

    mapping = malloc(sizeof(sr_nat_mapping_t);
    mapping->conns = NULL;
    mapping->aux_ext = natNextMappingNumber(nat, type);
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

    /* Add mapping to the front of the list */
    mapping->next = nat->mappings;
    nat->mappings = mapping;

    copy = malloc(sizeof(sr_nat_mapping_t);
    memcpy(copy, mapping, sizeof(sr_nat_mapping_t));

    pthread_mutex_unlock(&(nat->lock));
    return copy;
}

void nat_handle_ippacket(struct sr_instance *sr,
                        sr_ip_hdr_t *ipPacket, unsigned int length,
                        struct sr_if const *const r_interface)
{
    if (ipPacket->ip_p == ip_protocol_tcp)
    {
      natHandleTcpPacket(sr, ipPacket, length, r_interface);
    } else if (ipPacket->ip_p == ip_protocol_icmp)
    {
      natHandleIcmpPacket(sr, ipPacket, length, r_interface);
    } else {
        fprintf(stderr, "%sReceived packet of unknown IP protocol type %u. Dropping.\n", ipPacket->ip_p);
      }
}

static sr_nat_connection_t *sr_nat_lookup_connection(sr_nat_mapping_t *natEntry, uint32_t ip_ext, 
                                                    uint16_t port_ext)
{
    sr_nat_connection_t *conn_walker = natEntry->conns;
   
    while (conn_walker != NULL)
    {
      if ((conn_walker->external.ipAddress == ip_ext) 
         && (conn_walker->external.portNumber == port_ext))
      {
         conn_walker->lastAccessed = time(NULL);
         break;
      }
      
      conn_walker = conn_walker->next;
    }

    return conn_walker;
}

/*
* natHandleIcmpPacket()\n
* @brief Function processes an ICMP packet when NAT functionality is enabled. 
* @param sr pointer to simple router structure.
* @param ipPacket pointer to received IP datagram with an ICMP payload.
* @param length length of the IP datagram
* @param r_interface interface on which this packet was originally received.
*/
static void natHandleIcmpPacket(sr_instance_t *sr,
                               sr_ip_hdr_t *ipPacket, unsigned int length,
                               sr_if_t const *const r_interface)
{
    uint32_t ip_dst = ipPacket->ip_dsr;
    sr_icmp_hdr_t *icmpHeader = icmp_header(ipPacket);

    if (!icmp_validpacket(ipPacket));
    {
      return;
    }

    if ((sr_get_interface(sr, internal_if)->ip == r_interface->ip)
        && (sr_packet_is_for_me(sr, ip_dst)))
    {

      /* Packet is for me and it's from inside */
      IpHandleReceivedPacketToUs(sr, ipPacket, length, r_interface);
    }
    else if (sr_get_interface(sr, internal_if)->ip == r_interface->ip)
    {

      /* Outbound packet */
      if ((icmpHeader->icmp_type == icmp_type_echo_request)
         || (icmpHeader->icmp_type == icmp_type_echo_reply))
      {
        sr_icmp_hdr_t *icmpPingHdr = (sr_icmp_hdr_t *)icmpHeader;
        sr_nat_mapping_t *natLookupResult = sr_nat_lookup_internal(sr->nat, ipPacket->ip_src,
                                                                  icmpPingHdr->ident, nat_mapping_icmp);

        /* If mapping doesn't exist, create one */
        if (natLookupResult == NULL)
        {
          natLookupResult = sr_nat_insert_mapping(sr->nat, ipPacket->ip_src,
                                                 icmpPingHdr->ident, nat_mapping_icmp);
        }
        natHandleReceivedOutboundIpPacket(sr, ipPacket, length, r_interface, natLookupResult);
        free(natLookupResult);
      } else {
          sr_ip_hdr_t *embeddedIpPacket = NULL;
          sr_nat_mapping_t *natLookupResult = NULL;

          if ((icmpHeader->icmp_type == icmp_type_desination_unreachable)
             || (icmpHeader->icmp_type == icmp_type_time_exceeded))
          {
            sr_icmp_t3_hdr_t *unreachableHeader = (sr_icmp_t3_hdr_t *)icmpHeader;
            embeddedIpPacket = (sr_ip_hdr_t *)unreachableHeader->data;
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
            if ((embeddedIcmpHeader->icmp_type == icmp_type_echo_request)
               || (embeddedIcmpHeader->icmp_type == icmp_type_echo_reply))
            {
              natLookupResult = sr_nat_lookup_internal(sr->nat, embeddedIpPacket->ip_dst,
                                                      embeddedIcmpHeader->ident, nat_mapping_icmp);
            }
            /* Otherwise, we will not have a mapping for this ICMP type. */
            /* Either way, echo request and echo reply are the only ICMP */
            /* packet types that can generate another ICMP packet. */ 
          }
          else if(embeddedIpPacket->ip_p == ip_protocol_tcp)
          {
            sr_tcp_hdr_t *embeddedTcpHeader = tcp_header(embeddedIpPacket);
            natLookupResult = sr_nat_lookup_internal(sr->nat, embeddedIpPacket->ip_dst,
                                                    embeddedTcpHeader->destinationPort, nat_mapping_tcp);
          } else {
              return;
            }

          /* If hit the entry for that packet, modify and send it out */
          if (natLookupResult != NULL)
          {
            natHandleReceivedOutboundIpPacket(sr, ipPacket, length, r_interface, natLookupResult); 
            free(natLookupResult);
          }
        }
    } else {

        /* Inbound packet */
        if (!sr_packet_is_for_me(sr, ip_dst)) 
        {
          /* Packet no for me */
          struct sr_rt* lpmatch = longest_prefix_matching(sr, ipPacket->ip_dst);

          if ((sr_get_interface(sr,internalInterfaceName)->ip)
             != (sr_get_interface(sr,lpmatch->interface)->ip))
          {
          ip_forwardpacket(sr, ipPacket, length, receivedInterface->name)
          } else {
              printf("%sUnsolicited inbound ICMP packet received attempting to send to internal IP. Dropping.\n");
            }
          return;
        }
        else if (ip_dst == sr_get_interface(sr, internal_if)->ip)
        {
          /* For me but dst is internal interface */
          printf("%sReceived ICMP packet to our internal interface. Dropping.\n", );
          return;
        }
        else if ((icmpHeader->icmp_type == icmp_type_echo_request)
                || (icmpHeader->icmp_type == icmp_type_echo_reply))   /* For me & is echo_request/reply */
        {
          sr_icmp_t0_hdr_t icmp_ping_hdr = (sr_icmp_t0_hdr_t *)icmpHeader;
          sr_nat_mapping_t *natLookupResult = sr_nat_lookup_external(sr->nat, icmp_ping_hdr->ident,
                                                                    nat_mapping_icmp);

          if (natLookupResult == NULL)
          {
          
            /* No mapping exists. Assume ping is actually for us */
            IpHandleReceivedPacketToUs(sr, ipPacket, length, r_interface);
          } else {
              natHandleReceivedInboundIpPacket(sr, ipPacket, length, r_interface,natLookupResult);
              free (natLookupResult);
            }
        } else {

            /* For me & is ICMP error message */
            sr_ip_hdr_t *embeddedIpPacket = NULL;
            sr_nat_mapping_t *natLookupResult = NULL;

            if ((icmpHeader->icmp_type == type_dst_unreach)
               || (icmpHeader->icmp_type ==type_time_exceeded)
            {
              sr_icmp_t3_hdr_t *unreachableHeader = (sr_icmp_t3_hdr_t *)icmpHeader;
              embeddedIpPacket = (sr_ip_hdr_t *)unreachableHeader->data;
            } else {
                fprintf(stderr, "%sDropping unsupported inbound ICMP packet Type:\n", icmpHeader->icmp_type);
                fprintf(stderr, "%sCode:\n", icmpHeader->icmp_code ); 
                return;
              }
            assert(embeddedIpPacket);

            if (embeddedIpPacket->ip_p == ip_protocol_icmp)
            {
              sr_icmp_t0_hdr_t *embeddedIcmpHeader = (sr_icmp_t0_hdr_t *)icmp_header(embeddedIpPacket);

              if ((embeddedIcmpHeader->icmp_type == icmp_type_echo_request)
                 || (embeddedIcmpHeader->icmp_type == icmp_type_echo_reply))
              {
                natLookupResult = sr_nat_lookup_external(sr->nat, embeddedIcmpHeader->ident, nat_mapping_icmp);
              }
            /* Otherwise, we will not have a mapping for this ICMP type
            Either way, echo request and echo reply are the only ICMP packet types that can generate another ICMP packet */
            }
            else if (embeddedIpPacket->ip_p == ip_protocol_tcp)
            {
              sr_tcp_hdr_t * embeddedTcpHeader = tcp_header(embeddedIpPacket);
              natLookupResult = sr_nat_lookup_external(sr->nat, embeddedTcpHeader->sourcePort, nat_mapping_tcp);
            } else {
                /* Unsupported protocol, drop the packet */
                return;
              }
            if (natLookupResult != NULL)
            {
              natHandleReceivedInboundIpPacket(sr, ipPacket, length, r_interface, natLookupResult);
              free(natLookupResult);
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
* @param r_interface interface on which this packet was originally received.
*/

static void natHandleTcpPacket(sr_instance_t *sr, sr_ip_hdr_t *ipPacket, unsigned int length,
                              sr_if_t const *const r_interface)
{

    sr_tcp_hdr_t *tcpHeader = tcp_header(ipPacket);
    uint8_t icmp_type;
    uint8_t icmp_code;

    /* Valid TCP packet */  
    if (!tcp_validpacket(ipPacket))
    {
      return;
    }
   
    if ((sr_get_interface(sr, internal_if)->ip == r_interface->ip)
       && (sr_packet_is_for_me(sr, ipPacket->ip_dst)))
    {
      ip_handlepacketforme(sr, ipPacket, r_interface->name);
    }
    else if (sr_get_interface(sr, internal_if)->ip == r_interface->ip)
    {
      sr_nat_mapping_t *natMapping = sr_nat_lookup_internal(sr->nat, ipPacket->ip_src,
                                                            tcpHeader->sourcePort, nat_mapping_tcp);
      
      if (ntohs(tcpHeader->offset_controlBits) & TCP_SYN_Mask)
      {
        if (natMapping == NULL)
        {

          /* Outbound SYN with no existed mapping, create new entry */
          pthread_mutex_lock(&(sr->nat->lock));

          sr_nat_connection_t *firstConnection = malloc(sizeof(sr_nat_connection_t));
          sr_nat_mapping_t *sharedNatMapping;

          natMapping = malloc(sizeof(sr_nat_mapping_t));
          assert(firstConnection);
          assert(natMapping);
            
          sharedNatMapping = sr_nat_insert_mapping(sr->nat, ipPacket->ip_src,
                                                    tcpHeader->sourcePort, nat_mapping_tcp);
          assert(sharedNatMapping);
            
          /* Fill in first connection information */
          firstConnection->connectionState = nat_conn_outbound_syn;
          firstConnection->lastAccessed = time(NULL);
          firstConnection->queuedInboundSyn = NULL;
          firstConnection->external.ipAddress = ipPacket->ip_dst;
          firstConnection->external.portNumber = tcpHeader->destinationPort;
            
          /* Add to the list of connections */
          firstConnection->next = sharedNatMapping->conns;
          sharedNatMapping->conns = firstConnection;
            
          /* Create a copy so we can keep using it after we unlock the NAT table */
          memcpy(natMapping, sharedNatMapping, sizeof(sr_nat_mapping_t));
            
          pthread_mutex_unlock(&(sr->nat->lock));
        } else {

            /* Outbound SYN with prior mapping. Add the connection if one doesn't exist */
            pthread_mutex_lock(&(sr->nat->lock));

            sr_nat_mapping_t *sharedNatMapping = sr_nat_lookup_internal(sr->nat, ipPacket->ip_src,
                                                                       tcpHeader->sourcePort, nat_mapping_tcp);
            assert(sharedNatMapping);
            
            sr_nat_connection_t *connection = sr_nat_lookup_connection(sharedNatMapping,
                                                                      ipPacket->ip_dst, tcpHeader->destinationPort);  

            if (connection == NULL)
            {

              /* Connection does not exist. Create it */
              connection = malloc(sizeof(sr_nat_connection_t));
              assert(connection);
               
              /* Fill in connection information */
              connection->connectionState = nat_conn_outbound_syn;
              connection->external.ipAddress = ipPacket->ip_dst;
              connection->external.portNumber = tcpHeader->destinationPort;
               
              /* Add to the list of connections */
              connection->next = sharedNatMapping->conns;
              sharedNatMapping->conns = connection;
            }
            else if (connection->connectionState == nat_conn_time_wait)
            {

              /* Give client opportunity to reopen the connection */
              connection->connectionState = nat_conn_outbound_syn;
            }
            else if (connection->connectionState == nat_conn_inbound_syn_pending)
            {
              connection->connectionState = nat_conn_connected;
               
              if (connection->queuedInboundSyn) 
              {
                free(connection->queuedInboundSyn);
              }
            }

            pthread_mutex_unlock(&(sr->nat->lock));
          }
      }
      else if (natMapping == NULL)
      {
        /* Subsequent TCP packet without mapping  */
        return;
      }
      else if (ntohs(tcpHeader->offset_controlBits) & TCP_FIN_Mask)
      {
        /* Outbound FIN detected. Put connection into TIME_WAIT state */
        pthread_mutex_lock(&(sr->nat->lock));

        sr_nat_mapping_t *sharedNatMapping = sr_nat_lookup_internal(sr->nat, ipPacket->ip_src,
                                                                   tcpHeader->sourcePort, nat_mapping_tcp);
        sr_nat_connection_t *associatedConnection = sr_nat_lookup_connection(sharedNatMapping, ipPacket->ip_dst,
                                                                            tcpHeader->destinationPort);
         
        if (associatedConnection)
        {
          associatedConnection->connectionState = nat_conn_time_wait;
        }
         
        pthread_mutex_unlock(&sr->nat->lock);
      }
      
      /* Translate and forward */
      natHandleReceivedOutboundIpPacket(sr, ipPacket, length, r_interface, natMapping);

      if (natMapping) 
      { 
        free(natMapping);
      }
    } else {

      /* Inbound TCP packet */
      sr_nat_mapping_t *natMapping = sr_nat_lookup_external(sr->nat, tcpHeader->destinationPort,
                                                           nat_mapping_tcp);

      if (ntohs(tcpHeader->offset_controlBits) & TCP_SYN_Mask)
      {

        /* Inbound SYN received */
        struct sr_rt* lpmatch = longest_prefix_matching(sr, ipPacket->ip_src);

        if (natMapping == NULL)
        {
          /* Inbound TCP SYN without mapping, check destination port and send ICMP port unreachable denpending on it */
          if (tcpHeader->destinationPort >= 1024)
          {
            sleep(SIMULTANIOUS_OPEN_WAIT_TIME);
          }
          icmp_type = 3;
          icmp_code = 3;
          sr_icmp_with_payload(sr, ipPacket, lpmatch->interface, icmp_type, icmp_code);
            
          return;
        } else {

            /* Potential simultaneous open */
            pthread_mutex_lock(&sr->nat->lock);
            
            sr_nat_mapping_t *sharedNatMapping = sr_nat_lookup_external(sr->nat, tcpHeader->destinationPort,
                                                                         nat_mapping_tcp);
            assert(sharedNatMapping);
            
            sr_nat_connection_t *connection = sr_nat_lookup_connection(sharedNatMapping, ipPacket->ip_src,
                                                                      tcpHeader->sourcePort);

            if (connection == NULL)
            {
              /* Potential simultaneous open */
              connection = malloc(sizeof(sr_nat_connection_t));
              assert(connection);
               
              /* Fill in connection information */
              connection->connectionState = nat_conn_inbound_syn_pending;
              connection->queuedInboundSyn = malloc(length);
              memcpy(connection->queuedInboundSyn, ipPacket, length);
              connection->external.ipAddress = ipPacket->ip_src;
              connection->external.portNumber = tcpHeader->sourcePort;
               
              /* Add to the list of connections */
              connection->next = sharedNatMapping->conns;
              sharedNatMapping->conns = connection;
               
              return;
            }
            else if (connection->connectionState == nat_conn_inbound_syn_pending)
            {
              return;
            }
            else if (connection->connectionState == nat_conn_outbound_syn)
            {
               connection->connectionState = nat_conn_connected;
            }
            
            pthread_mutex_unlock(&(sr->nat->lock));
          }
      }
      else if (natMapping == NULL)
      {

        /* TCP packet attempted to traverse the NAT on an unopened */
        icmp_type = 3;
        icmp_code = 3;
        sr_icmp_with_payload(sr, ipPacket, lpmatch->interface, icmp_type, icmp_code);
        
        return;
      }
      else if (ntohs(tcpHeader->offset_controlBits) & TCP_FIN_Mask)
      {

        /* Inbound FIN detected. Put connection into TIME_WAIT state */
        pthread_mutex_lock(&sr->nat->lock);

        sr_nat_mapping_t *sharedNatMapping = sr_nat_lookup_external(sr->nat, tcpHeader->destinationPort,
                                                                   nat_mapping_tcp);
        sr_nat_connection_t *associatedConnection = sr_nat_lookup_connection(sharedNatMapping, ipPacket->ip_src,
                                                                            tcpHeader->sourcePort);         
        if (associatedConnection)
        {
          associatedConnection->connectionState = nat_conn_time_wait;
        }
         
        pthread_mutex_unlock(&(sr->nat->lock));
      } else {

          /* Lookup the associated connection */
          pthread_mutex_lock(&(sr->nat->lock));

          sr_nat_mapping_t *sharedNatMapping = sr_nat_lookup_external((sr->nat, tcpHeader->destinationPort,
                                                                     nat_mapping_tcp);
          sr_nat_connection_t *associatedConnection = sr_nat_lookup_connection(sharedNatMapping, ipPacket->ip_src,
                                                                              tcpHeader->sourcePort);         
          if (associatedConnection == NULL)
          {

            /* Received unsolicited non-SYN packet when no active connection was found */
            pthread_mutex_unlock(&(sr->nat->lock));

            return;
          } else {
              pthread_mutex_unlock(&(sr->nat->lock));
            }
        }
      
      natHandleReceivedInboundIpPacket(sr, ipPacket, length, r_interface, natMapping);
      
      if (natMapping) 
      { 
        free(natMapping);
      }
    }
}

static void natHandleReceivedOutboundIpPacket(struct sr_instance* sr, sr_ip_hdr_t* packet, unsigned int length, const struct sr_if* const r_interface, sr_nat_mapping_t * natMapping)
{
 if (packet->ip_p == ip_protocol_icmp)
  { sr_icmp_hdr_t *icmpPacketHeader = icmp_header(packet);\
   if ((icmpPacketHeader->icmp_type == icmp_type_echo_request) || (icmpPacketHeader->icmp_type == icmp_type_echo_reply))
   {
    sr_icmp_t0_hdr_t* rewrittenIcmpHeader = (sr_icmp_t0_hdr_t*) icmpPacketHeader;
    int icmpLength = length - packet->ip_hl * 4;
    assert(natMapping);

         /* Handle ICMP identify remap and validate. */
    rewrittenIcmpHeader->ident = natMapping->aux_ext;
    rewrittenIcmpHeader->icmp_sum = 0;
    rewrittenIcmpHeader->icmp_sum = cksum(rewrittenIcmpHeader, icmpLength);

         /* Handle IP address remap and validate. */
    packet->ip_src = sr_get_interface(sr,longest_prefix_matching(sr, packet->ip_dst)->interface)->ip;

    ip_forwardpacket(sr, packet, length, r_interface->name);
  }
  else
  {
   int icmpLength = length - packet->ip_hl * 4;
   sr_ip_hdr_t * originalDatagram;
   if (icmpPacketHeader->icmp_type == icmp_type_desination_unreachable)
   {
     /* This packet is actually associated with a stream. */
    sr_icmp_t3_hdr_t *unreachablePacketHeader = (sr_icmp_t3_hdr_t *) icmpPacketHeader;
    originalDatagram = (sr_ip_hdr_t*) (unreachablePacketHeader->data);
   }
  else if (icmpPacketHeader->icmp_type == icmp_type_time_exceeded)
  {
    sr_icmp_t11_hdr_t *unreachablePacketHeader = (sr_icmp_t11_hdr_t *) icmpPacketHeader;
    originalDatagram = (sr_ip_hdr_t*) (unreachablePacketHeader->data);
  }
  
  assert(natMapping);
  
  if (originalDatagram->ip_p == ip_protocol_tcp)
  {
    sr_tcp_hdr_t *originalTransportHeader = tcp_header(originalDatagram);
    
            /* Perform mapping on embedded payload */
    originalTransportHeader->destinationPort = natMapping->aux_ext;
    originalDatagram->ip_dst = sr_get_interface(sr,longest_prefix_match(sr,packet->ip_dst)->interface)->ip;
  }
  else if (originalDatagram->ip_p == ip_protocol_icmp)
  {
    sr_icmp_t0_hdr_t *originalTransportHeader =
    (sr_icmp_t0_hdr_t *) getIcmpHeaderFromIpHeader(originalDatagram);
    
            /* Perform mapping on embedded payload */
    originalTransportHeader->ident = natMapping->aux_ext;
    originalDatagram->ip_dst = sr_get_interface(sr, longest_prefix_match(sr, packet->ip_dst)->interface)->ip;
  }
  
         /* Update ICMP checksum */
  icmpPacketHeader->icmp_sum = 0;
  icmpPacketHeader->icmp_sum = cksum(icmpPacketHeader, icmpLength);
  
         /* Rewrite actual packet header. */
    packet->ip_src = sr_get_interface(sr,longest_prefix_macth(sr, packet->ip_dst)->interface)->ip;
  
  ip_forwardpacket(sr, packet, length, r_interface);
}



}
 else if (packet->ip_p == ip_protocol_tcp)
 {
  sr_tcp_hdr_t* tcpHeader = tcp_header(packet);
      
      tcpHeader->sourcePort = natMapping->aux_ext;
      packet->ip_src = sr_get_interface(sr,
         IpGetPacketRoute(sr, ntohl(packet->ip_dst))->interface)->ip;
      
      natRecalculateTcpChecksum(packet, length);
      ip_forwardpacket(sr, packet, length, r_interface);
}

}

static void natHandleReceivedInboundIpPacket(struct sr_instance* sr, sr_ip_hdr_t* packet, 
   unsigned int length, const struct sr_if* const r_interface, sr_nat_mapping_t * natMapping)
{
   if (packet->ip_p == ip_protocol_icmp)
   {
      sr_icmp_hdr_t *icmpPacketHeader =icmp_header(packet);
      
      if ((icmpPacketHeader->icmp_type == icmp_type_echo_request) || (icmpPacketHeader->icmp_type == icmp_type_echo_reply))
      {
         sr_icmp_t0_hdr_t *echoPacketHeader = (sr_icmp_t0_hdr_t *) icmpPacketHeader;
         int icmpLength = length - packet->ip_hl * 4;
         
         assert(natMapping);
         
         /* Handle ICMP identify remap and validate. */
         echoPacketHeader->ident = natMapping->aux_int;
         echoPacketHeader->icmp_sum = 0;
         echoPacketHeader->icmp_sum = cksum(echoPacketHeader, icmpLength);
         
         /* Handle IP address remap and validate. */
         packet->ip_dst = natMapping->ip_int;
         
         ip_forwardpacket(sr, packet, length, r_interface->name);
      }
      else 
      {
         int icmpLength = length - packet->ip_hl * 4;
         sr_ip_hdr_t * originalDatagram;
         if (icmpPacketHeader->icmp_type == icmp_type_desination_unreachable)
         {
            /* This packet is actually associated with a stream. */
            sr_icmp_t3_hdr_t *unreachablePacketHeader = (sr_icmp_t3_hdr_t *) icmpPacketHeader;
            originalDatagram = (sr_ip_hdr_t*) (unreachablePacketHeader->data);
         }
         else if (icmpPacketHeader->icmp_type == icmp_type_time_exceeded)
         {
            sr_icmp_t3_hdr_t *unreachablePacketHeader = (sr_icmp_t3_hdr_t *) icmpPacketHeader;
            originalDatagram = (sr_ip_hdr_t*) (unreachablePacketHeader->data);
         }
            
         assert(natMapping);
         
         if (originalDatagram->ip_p == ip_protocol_tcp)
         {
            sr_tcp_hdr_t *originalTransportHeader = tcp_header(originalDatagram);
            
            /* Perform mapping on embedded payload */
            originalTransportHeader->sourcePort = natMapping->aux_int;
            originalDatagram->ip_src = natMapping->ip_int;
         }
         else if (originalDatagram->ip_p == ip_protocol_icmp)
         {
            sr_icmp_t0_hdr_t *originalTransportHeader =
               (sr_icmp_t0_hdr_t *) icmp_header(originalDatagram);
            
            /* Perform mapping on embedded payload */
            originalTransportHeader->ident = natMapping->aux_int;
            originalDatagram->ip_src = natMapping->ip_int;
         }
         
         /* Update ICMP checksum */
         icmpPacketHeader->icmp_sum = 0;
         icmpPacketHeader->icmp_sum = cksum(icmpPacketHeader, icmpLength);
         
         /* Rewrite actual packet header. */
         packet->ip_dst = natMapping->ip_int;
         
         ip_forwardpacket(sr, packet, length, r_interface->name);
      }
   }
   else if (packet->ip_p == ip_protocol_tcp)
   {
      sr_tcp_hdr_t* tcpHeader =tcp_header(packet);
            
      tcpHeader->destinationPort = natMapping->aux_int;
      packet->ip_dst = natMapping->ip_int;
      
      natRecalculateTcpChecksum(packet, length);
      ip_forwardpacket(sr, packet, length, r_interface->name);
   }
}


/**
 * natRecalculateTcpChecksum()\n
 * @brief Helper function for recalculating a TCP packet checksum after it has been altered.
 * @param tcpPacket pointer to the IP datagram containing the TCP packet
 * @param length length of the IP datagram in bytes
 * @note The pointer is to the IP datagram rather than the TCP payload since 
 *       some of the information in the IP header is needed to form the TCP 
 *       pseudo-header for calculating the checksum.
 */
static void natRecalculateTcpChecksum(sr_ip_hdr_t * tcpPacket, unsigned int length)
{
   unsigned int tcpLength = length - tcpPacket->ip_hl * 4;
   uint8_t *packetCopy = malloc(sizeof(sr_tcp_ip_pseudo_hdr_t) + tcpLength);

   sr_tcp_ip_pseudo_hdr_t * checksummedHeader = (sr_tcp_ip_pseudo_hdr_t *) packetCopy;
   sr_tcp_hdr_t * const tcpHeader = (sr_tcp_hdr_t * const ) (((uint8_t*) tcpPacket)
      + getIpHeaderLength(tcpPacket));
   
   /* I wish there was a better way to do this with pointer magic, but I don't 
    * see it. Make a copy of the packet and prepend the IP pseudo-header to 
    * the front. */
   memcpy(packetCopy + sizeof(sr_tcp_ip_pseudo_hdr_t), tcpHeader, tcpLength);
   checksummedHeader->sourceAddress = tcpPacket->ip_src;
   checksummedHeader->destinationAddress = tcpPacket->ip_dst;
   checksummedHeader->zeros = 0;
   checksummedHeader->protocol = ip_protocol_tcp;
   checksummedHeader->tcpLength = htons(tcpLength);
   
   tcpHeader->checksum = 0;
   tcpHeader->checksum = cksum(packetCopy, sizeof(sr_tcp_ip_pseudo_hdr_t) + tcpLength);
   
   free(packetCopy);
}


static void sr_nat_destroy_connection (sr_nat_mapping_t* natMapping, sr_nat_connection * connection)
{
sr_nat_connection_t *req, *prev = NULL, *next = NULL;
   
   if (natMapping && connection)
   {
      for (req = natMapping->conns; req != NULL; req = req->next)
      {
         if (req == connection)
         {
            if (prev)
            {
               next = req->next;
               prev->next = next;
            }
            else
            {
               next = req->next;
               natMapping->conns = next;
            }
            
            break;
         }
         prev = req;
      }
      
      if(connection->queuedInboundSyn)
      {
         free(connection->queuedInboundSyn);
      }
      
      free(connection);
   }
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
