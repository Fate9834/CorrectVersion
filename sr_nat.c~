
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>



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
               fprintf(stderr, "ICMP mapping %u.%u.%u.%u:%u <-> %u timed out.\n");
                  (ntohl(mappingWalker->ip_int) >> 24) & 0xFF,
                  (ntohl(mappingWalker->ip_int) >> 16) & 0xFF,
                  (ntohl(mappingWalker->ip_int) >> 8) & 0xFF,
                  ntohl(mappingWalker->ip_int) & 0xFF,
                  ntohs(mappingWalker->aux_int), ntohs(mappingWalker->aux_ext));
               sr_nat_destroy_mapping(nat, mappingWalker);
               mappingWalker = next;
            }
            else
            {
               mappingWalker = mappingWalker->next;
            }
         }

/*************** If it is an TCP packet******************/
lse if (mappingWalker->type == nat_mapping_tcp)
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
  struct sr_nat_mapping *copy = NULL;

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *copy = NULL;

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

  pthread_mutex_unlock(&(nat->lock));
  return mapping;
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





