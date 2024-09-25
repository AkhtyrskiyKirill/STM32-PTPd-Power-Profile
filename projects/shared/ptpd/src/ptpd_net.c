#include <string.h>
#include "lwip/inet.h"
#include "lwip/udp.h"
#include "lwip/igmp.h"
#include "syslog.h"
#include "ptpd.h"
#include "ethernetif.h"

#ifdef PTPD_POWER_PROFILE
#include "lwip/netif.h"
#include "netif/ethernet.h"

struct ptpd_pcb ptpd_pcb_event;
struct ptpd_pcb ptpd_pcb_general;

#endif

#if LWIP_PTPD

// Initialize the network queue.
static void ptpd_net_queue_init(BufQueue *queue)
{
  queue->head = 0;
  queue->tail = 0;
  sys_mutex_new(&queue->mutex);
}

// Put data to the network queue.
static bool ptpd_net_queue_put(BufQueue *queue, void *pbuf)
{
  bool retval = false;

  sys_mutex_lock(&queue->mutex);

  // Is there room on the queue for the buffer?
  if (((queue->head + 1) & PBUF_QUEUE_MASK) != queue->tail)
  {
    // Place the buffer in the queue.
    queue->head = (queue->head + 1) & PBUF_QUEUE_MASK;
    queue->pbuf[queue->head] = pbuf;
    retval = true;
  }

  sys_mutex_unlock(&queue->mutex);

  return retval;
}

// Get data from the network queue.
static void *ptpd_net_queue_get(BufQueue *queue)
{
  void *pbuf = NULL;

  sys_mutex_lock(&queue->mutex);

  // Is there a buffer on the queue?
  if (queue->tail != queue->head)
  {
    // Get the buffer from the queue.
    queue->tail = (queue->tail + 1) & PBUF_QUEUE_MASK;
    pbuf = queue->pbuf[queue->tail];
  }

  sys_mutex_unlock(&queue->mutex);

  return pbuf;
}

// Free any remaining pbufs in the queue.
static void ptpd_net_queue_empty(BufQueue *queue)
{
  sys_mutex_lock(&queue->mutex);

  // Free each remaining buffer in the queue.
  while (queue->tail != queue->head)
  {
    // Get the buffer from the queue.
    queue->tail = (queue->tail + 1) & PBUF_QUEUE_MASK;
    pbuf_free(queue->pbuf[queue->tail]);
  }
  
  sys_mutex_unlock(&queue->mutex);
}

// Return true if something is in the queue.
static bool ptpd_net_queue_check(BufQueue  *queue)
{
  bool  retval = false;

  sys_mutex_lock(&queue->mutex);

  if (queue->tail != queue->head) retval = true;

  sys_mutex_unlock(&queue->mutex);

  return retval;
}

#ifndef PTPD_POWER_PROFILE

// Find interface to be used. uuid will be filled with MAC address of the interface.
// The IPv4 address of the interface will be returned.
static int32_t ptpd_find_iface(const octet_t *ifaceName, octet_t *uuid, NetPath *net_path)
{
  struct netif *iface;

  // Use the default interface.
  iface = netif_default;

  // Copy the interface hardware address.
  memcpy(uuid, iface->hwaddr, iface->hwaddr_len);

  // Return the interface IP address.
  return iface->ip_addr.addr;
}

// Process an incoming message on the event port.
static void ptpd_net_event_callback(void *arg, struct udp_pcb *pcb, struct pbuf *p,
                                    const ip_addr_t *addr, u16_t port)
{
  NetPath *net_path = (NetPath *) arg;

  // Place the incoming message on the event port queue.
  if (ptpd_net_queue_put(&net_path->eventQ, p))
  {
    // Alert the PTP thread there is now something to do.
    ptpd_alert();
  }
  else
  {
    pbuf_free(p);
    syslog_printf(SYSLOG_ERROR, "PTPD: event port queue full");
    ERROR("PTPD: event port queue full\n");
  }
}

// Process an incoming message on the general port.
static void ptpd_net_general_callback(void *arg, struct udp_pcb *pcb, struct pbuf *p,
                                      const ip_addr_t *addr, u16_t port)
{
  NetPath *net_path = (NetPath *) arg;

  // Place the incoming message on the event port queue.
  if (ptpd_net_queue_put(&net_path->generalQ, p))
  {
    // Alert the PTP thread there is now something to do.
    ptpd_alert();
  }
  else
  {
    pbuf_free(p);
    syslog_printf(SYSLOG_ERROR, "PTPD: general port queue full");
    ERROR("PTPD: general port queue full\n");
  }
}

// Start all of the UDP stuff.
bool ptpd_net_init(NetPath *net_path, PtpClock *ptp_clock)
{
  in_addr_t net_addr;
  ip_addr_t interface_addr;
  char addr_str[NET_ADDRESS_LENGTH];

  // Initialize the buffer queues.
  ptpd_net_queue_init(&net_path->eventQ);
  ptpd_net_queue_init(&net_path->generalQ);

  // Find a network interface.
  interface_addr.addr = ptpd_find_iface(ptp_clock->rtOpts.ifaceName, ptp_clock->portUuidField, net_path);
  if (!(interface_addr.addr))
  {
    syslog_printf(SYSLOG_CRITICAL, "PTPD: failed to find interface address");
    ERROR("PTPD: Failed to find interface address\n");
    goto fail01;
  }

  // Open lwip raw udp interfaces for the event port.
  net_path->eventPcb = udp_new();
  if (NULL == net_path->eventPcb)
  {
    syslog_printf(SYSLOG_CRITICAL, "PTPD: failed to create event UDP PCB");
    ERROR("PTPD: Failed to open event UDP PCB\n");
    goto fail02;
  }

  // Open lwip raw udp interfaces for the general port.
  net_path->generalPcb = udp_new();
  if (NULL == net_path->generalPcb)
  {
    syslog_printf(SYSLOG_CRITICAL, "PTPD: failed to create general UDP PCB");
    ERROR("PTPD: Failed to open general UDP PCB\n");
    goto fail03;
  }

  // Configure network (broadcast/unicast) addresses (unicast disabled).
  net_path->unicastAddr = 0;

  // Init general multicast IP address.
  memcpy(addr_str, DEFAULT_PTP_DOMAIN_ADDRESS, NET_ADDRESS_LENGTH);
  if (!inet_aton(addr_str, &net_addr))
  {
    syslog_printf(SYSLOG_CRITICAL, "PTPD: failed to encode multi-cast address: %s", addr_str);
    ERROR("PTPD: failed to encode multi-cast address: %s\n", addr_str);
    goto fail04;
  }
  net_path->multicastAddr = net_addr;

  // Join multicast group (for receiving) on specified interface.
  igmp_joingroup(&interface_addr, (ip4_addr_t *) &net_addr);

  // Init peer multicast IP address.
  memcpy(addr_str, PEER_PTP_DOMAIN_ADDRESS, NET_ADDRESS_LENGTH);
  if (!inet_aton(addr_str, &net_addr))
  {
    syslog_printf(SYSLOG_CRITICAL, "PTPD: failed to encode peer multi-cast address: %s", addr_str);
    ERROR("PTPD: failed to encode peer multi-cast address: %s\n", addr_str);
    goto fail04;
  }
  net_path->peerMulticastAddr = net_addr;

  // Join peer multicast group (for receiving) on specified interface.
  igmp_joingroup(&interface_addr, (ip4_addr_t *) &net_addr);

  // Multicast send only on specified interface.
  net_path->eventPcb->mcast_ip4.addr = net_path->multicastAddr;
  net_path->generalPcb->mcast_ip4.addr = net_path->multicastAddr;

  // Establish the appropriate UDP bindings/connections for event port.
  udp_recv(net_path->eventPcb, ptpd_net_event_callback, net_path);
  udp_bind(net_path->eventPcb, IP_ADDR_ANY, PTP_EVENT_PORT);
  // udp_connect(net_path->eventPcb, &net_addr, PTP_EVENT_PORT);

  // Establish the appropriate UDP bindings/connections for general port.
  udp_recv(net_path->generalPcb, ptpd_net_general_callback, net_path);
  udp_bind(net_path->generalPcb, IP_ADDR_ANY, PTP_GENERAL_PORT);
  // udp_connect(net_path->generalPcb, &net_addr, PTP_GENERAL_PORT);

  // Return success.
  return true;

fail04:
  udp_remove(net_path->generalPcb);
fail03:
  udp_remove(net_path->eventPcb);
fail02:
fail01:
  return false;
}

// Shut down the UDP and network stuff.
bool ptpd_net_shutdown(NetPath *net_path)
{
  ip_addr_t multicast_addr;

  DBG("ptpd_net_shutdown\n");

  // Leave multicast group.
  multicast_addr.addr = net_path->multicastAddr;
  if (multicast_addr.addr) igmp_leavegroup(IP_ADDR_ANY, &multicast_addr);

  // Disconnect and close the event UDP interface.
  if (net_path->eventPcb)
  {
    udp_disconnect(net_path->eventPcb);
    udp_remove(net_path->eventPcb);
    net_path->eventPcb = NULL;
  }

  // Disconnect and close the general UDP interface.
  if (net_path->generalPcb)
  {
    udp_disconnect(net_path->generalPcb);
    udp_remove(net_path->generalPcb);
    net_path->generalPcb = NULL;
  }

  // Clear the network addresses.
  net_path->multicastAddr = 0;
  net_path->unicastAddr = 0;

  // Return success.
  return true;
}

#else

// Find interface to be used. uuid will be filled with MAC address of the interface.
static void ptpd_find_iface(const octet_t *ifaceName, octet_t *uuid, NetPath *net_path)
{
  struct netif *iface;

  // Use the default interface.
  iface = netif_default;

  // Copy the interface hardware address.
  memcpy(uuid, iface->hwaddr, iface->hwaddr_len);

}

// Process an incoming message on the event port.
static void ptpd_net_event_callback(void *arg, struct pbuf *p)
{
  NetPath *net_path = (NetPath *) arg;

  // Place the incoming message on the event port queue.
  if (ptpd_net_queue_put(&net_path->eventQ, p))
  {
    // Alert the PTP thread there is now something to do.
    ptpd_alert();
  }
  else
  {
    pbuf_free(p);
    syslog_printf(SYSLOG_ERROR, "PTPD: event port queue full");
    ERROR("PTPD: event port queue full\n");
  }
}

// Process an incoming message on the general port.
static void ptpd_net_general_callback(void *arg, struct pbuf *p)
{
  NetPath *net_path = (NetPath *) arg;

  // Place the incoming message on the event port queue.
  if (ptpd_net_queue_put(&net_path->generalQ, p))
  {
    // Alert the PTP thread there is now something to do.
    ptpd_alert();
  }
  else
  {
    pbuf_free(p);
    syslog_printf(SYSLOG_ERROR, "PTPD: general port queue full");
    ERROR("PTPD: general port queue full\n");
  }
}

// Start Power Profile
bool ptpd_net_init(NetPath *net_path, PtpClock *ptp_clock)
{

  // Initialize the buffer queues.
  ptpd_net_queue_init(&net_path->eventQ);
  ptpd_net_queue_init(&net_path->generalQ);

	// Find a network interface.
  ptpd_find_iface(ptp_clock->rtOpts.ifaceName, ptp_clock->portUuidField, net_path);
	
	// Configure network multicast MAC address
	net_path->multicastMac[0] = DEFAULT_MULTICAST_MAC0;
	net_path->multicastMac[1] = DEFAULT_MULTICAST_MAC1;
	net_path->multicastMac[2] = DEFAULT_MULTICAST_MAC2;
	net_path->multicastMac[3] = DEFAULT_MULTICAST_MAC3;
	net_path->multicastMac[4] = DEFAULT_MULTICAST_MAC4;
	net_path->multicastMac[5] = DEFAULT_MULTICAST_MAC5;
	
	// Configure network multicast MAC address
	net_path->peerMulticastMac[0] = PEER_MULTICAST_MAC0;
	net_path->peerMulticastMac[1] = PEER_MULTICAST_MAC1;
	net_path->peerMulticastMac[2] = PEER_MULTICAST_MAC2;
	net_path->peerMulticastMac[3] = PEER_MULTICAST_MAC3;
	net_path->peerMulticastMac[4] = PEER_MULTICAST_MAC4;
	net_path->peerMulticastMac[5] = PEER_MULTICAST_MAC5;
	
  // Configure network (broadcast/unicast) MAC addresses (unicast disabled).
  net_path->unicastMac[0] = 0;
	net_path->unicastMac[1] = 0;
	net_path->unicastMac[2] = 0;
	net_path->unicastMac[3] = 0;
	net_path->unicastMac[4] = 0;
	net_path->unicastMac[5] = 0;

	// Configure ptp event and general message handlers
	ptpd_pcb_event.recv = ptpd_net_event_callback;
	ptpd_pcb_event.recv_arg = net_path;
	
	ptpd_pcb_general.recv = ptpd_net_general_callback;
	ptpd_pcb_general.recv_arg = net_path;
	
  // Return success.
  return true;
	
}

// Shut down PowerProfile
bool ptpd_net_shutdown(NetPath *net_path)
{

  DBG("ptpd_net_shutdown\n");

  // Clear the network addresses.
  net_path->multicastMac[0] = 0;
	net_path->multicastMac[1] = 0;
	net_path->multicastMac[2] = 0;
	net_path->multicastMac[3] = 0;
	net_path->multicastMac[4] = 0;
	net_path->multicastMac[5] = 0;

	net_path->peerMulticastMac[0] = 0;
	net_path->peerMulticastMac[1] = 0;
	net_path->peerMulticastMac[2] = 0;
	net_path->peerMulticastMac[3] = 0;
	net_path->peerMulticastMac[4] = 0;
	net_path->peerMulticastMac[5] = 0;
	
  net_path->unicastMac[0] = 0;
	net_path->unicastMac[1] = 0;
	net_path->unicastMac[2] = 0;
	net_path->unicastMac[3] = 0;
	net_path->unicastMac[4] = 0;
	net_path->unicastMac[5] = 0;

	// Clear ptp event and general message handlers
	ptpd_pcb_event.recv = NULL;
	ptpd_pcb_event.recv_arg = NULL;
	
	ptpd_pcb_general.recv = NULL;
	ptpd_pcb_general.recv_arg = NULL;

  // Return success.
  return true;
}

// PTP Power Profile message handler
void ptpd_net_input(struct pbuf *p, struct netif *netif) {
	
	// Taking MsgType field from header to check the PTP message type
	MsgHeader * msghdr = (MsgHeader *)p->payload;
	uint8_t msgType = (*(enum4bit_t*)(msghdr + 0)) & 0x0F;
	switch (msgType) {
		
		/* If event message */
		case 0x0:
		case 0x1:
		case 0x2:
		case 0x3:
			
		  /* callback */
      if (ptpd_pcb_event.recv != NULL) {
        /* now the recv function is responsible for freeing p */
        ptpd_pcb_event.recv(ptpd_pcb_event.recv_arg, p);
      } else {
        /* no recv function registered? then we have to free the pbuf! */
        pbuf_free(p);
      }
		
			break;
		
		/* If general message */
		case 0x8:
		case 0x9:
		case 0xA:
		case 0xB:
		case 0xC:
		case 0xD:
			
			/* callback */
      if (ptpd_pcb_general.recv != NULL) {
        /* now the recv function is responsible for freeing p */
        ptpd_pcb_general.recv(ptpd_pcb_general.recv_arg, p);
      } else {
        /* no recv function registered? then we have to free the pbuf! */
        pbuf_free(p);
      }
		
			break;
	}
		
	
}

#endif

// Wait for a packet  to come in on either port.  For now, there is no wait.
// Simply check to  see if a packet is available on either port and return 1,
// otherwise return 0.
int32_t ptpd_net_select(NetPath *net_path, const TimeInternal *timeout)
{
  // Check the packet queues.  If there is data, return true.
  if (ptpd_net_queue_check(&net_path->eventQ) || ptpd_net_queue_check(&net_path->generalQ)) return 1;

  return 0;
}

// Delete all waiting packets in event queue.
void ptpd_net_empty_event_queue(NetPath *net_path)
{
  ptpd_net_queue_empty(&net_path->eventQ);
}

// Receive the next buffer from the given queue.
static ssize_t ptpd_net_recv(octet_t *buf, TimeInternal *time, BufQueue *queue)
{
  int i;
  int j;
  u16_t length;
  struct pbuf *p;
  struct pbuf *pcopy;

  // Get the next buffer from the queue.
  if ((p = (struct pbuf*) ptpd_net_queue_get(queue)) == NULL)
  {
    return 0;
  }

  // Verify that we have enough space to store the contents.
  if (p->tot_len > PACKET_SIZE)
  {
    syslog_printf(SYSLOG_ERROR, "PTPD: received truncated packet");
    ERROR("PTPD: received truncated message\n");
    pbuf_free(p);
    return 0;
  }

  // Verify there is contents to copy.
  if (p->tot_len == 0)
  {
    syslog_printf(SYSLOG_ERROR, "PTPD: received empty packet");
    ERROR("PTPD: received empty packet\n");
    pbuf_free(p);
    return 0;
  }

  // Get the timestamp of the packet.
  if (time != NULL)
  {
    time->seconds = p->time_sec;
    time->nanoseconds = p->time_nsec;
  }

  // Get the length of the buffer to copy.
  length = p->tot_len;

  // Copy the pbuf payload into the buffer.
  pcopy = p;
  j = 0;
  for (i = 0; i < length; i++)
  {
    // Copy the next byte in the payload.
    buf[i] = ((u8_t *)pcopy->payload)[j++];

    // Skip to the next buffer in the payload?
    if (j == pcopy->len)
    {
      // Move to the next buffer.
      pcopy = pcopy->next;
      j = 0;
    }
  }

  // Free up the pbuf (chain).
  pbuf_free(p);

  return length;
}

ssize_t ptpd_net_recv_event(NetPath *net_path, octet_t *buf, TimeInternal *time)
{
  return ptpd_net_recv(buf, time, &net_path->eventQ);
}

ssize_t ptpd_net_recv_general(NetPath *net_path, octet_t *buf, TimeInternal *time)
{
  return ptpd_net_recv(buf, time, &net_path->generalQ);
}

#ifndef PTPD_POWER_PROFILE

static ssize_t ptpd_net_send(const octet_t *buf, int16_t  length, TimeInternal *time, const int32_t * addr, struct udp_pcb * pcb)
{
  err_t result;
  struct pbuf *p;

  // Allocate the tx pbuf based on the current size.
  p = pbuf_alloc(PBUF_TRANSPORT, length, PBUF_RAM);
  if (NULL == p)
  {
    syslog_printf(SYSLOG_ERROR, "PTPD: failed to allocate transmit protocol buffer");
    ERROR("PTPD: Failed to allocate transmit protocol buffer\n");
    goto fail01;
  }

  // Copy the incoming data into the pbuf payload.
  result = pbuf_take(p, buf, length);
  if (ERR_OK != result)
  {
    syslog_printf(SYSLOG_ERROR, "PTPD: failed to copy data into protocol buffer (%d)", result);
    ERROR("PTPD: Failed to copy data into protocol buffer (%d)\n", result);
    length = 0;
    goto fail02;
  }

  // Send the buffer.
  result = udp_sendto(pcb, p, (void *)addr, pcb->local_port);
  if (ERR_OK != result)
  {
    syslog_printf(SYSLOG_ERROR, "PTPD: failed to send data (%d)", result);
    ERROR("PTPD: Failed to send data (%d)\n", result);
    length = 0;
    goto fail02;
  }

#if defined(STM32F4) || defined(STM32F7)
  // Fill in the timestamp of the buffer just sent.
  if (time != NULL)
  {
    // We have special call back into the Ethernet interface to fill the timestamp
    // of the buffer just transmitted. This call will block for up to a certain amount
    // of time before it may fail if a timestamp was not obtained.
    ethernetif_get_tx_timestamp(p);
  }
#endif

  // Get the timestamp of the sent buffer.  We avoid overwriting 
  // the time if it looks to be an invalid zero value.
  if ((time != NULL) && (p->time_sec != 0))
  {
    time->seconds = p->time_sec;
    time->nanoseconds = p->time_nsec;
    DBGV("PTPD: %d sec %d nsec\n", time->seconds, time->nanoseconds);
  }

fail02:
  pbuf_free(p);

fail01:
  return length;
}

#else

// Send function for Power Profile
static ssize_t ptpd_net_send(const octet_t *buf, int16_t  length, TimeInternal *time, const uint8_t * addr)
{
  err_t result;
  struct pbuf *p;

  // Allocate the tx pbuf based on the current size.
  p = pbuf_alloc(PBUF_TRANSPORT, length, PBUF_RAM);
  if (NULL == p)
  {
    syslog_printf(SYSLOG_ERROR, "PTPD: failed to allocate transmit protocol buffer");
    ERROR("PTPD: Failed to allocate transmit protocol buffer\n");
    goto fail01;
  }

  // Copy the incoming data into the pbuf payload.
  result = pbuf_take(p, buf, length);
  if (ERR_OK != result)
  {
    syslog_printf(SYSLOG_ERROR, "PTPD: failed to copy data into protocol buffer (%d)", result);
    ERROR("PTPD: Failed to copy data into protocol buffer (%d)\n", result);
    length = 0;
    goto fail02;
  }

	//struct netif * netif = netif_find("st");
	// Use default interface
	struct netif * netif = netif_default;
	
	
  // Send the buffer.
	result = ethernet_output(netif, p, (struct eth_addr *)(netif->hwaddr), (struct eth_addr *)(addr), ETHTYPE_PTP);
  if (ERR_OK != result)
  {
    syslog_printf(SYSLOG_ERROR, "PTPD: failed to send data (%d)", result);
    ERROR("PTPD: Failed to send data (%d)\n", result);
    length = 0;
    goto fail02;
  }

#if defined(STM32F4) || defined(STM32F7)
  // Fill in the timestamp of the buffer just sent.
  if (time != NULL)
  {
    // We have special call back into the Ethernet interface to fill the timestamp
    // of the buffer just transmitted. This call will block for up to a certain amount
    // of time before it may fail if a timestamp was not obtained.
    ethernetif_get_tx_timestamp(p);
  }
#endif

  // Get the timestamp of the sent buffer.  We avoid overwriting 
  // the time if it looks to be an invalid zero value.
  if ((time != NULL) && (p->time_sec != 0))
  {
    time->seconds = p->time_sec;
    time->nanoseconds = p->time_nsec;
    DBGV("PTPD: %d sec %d nsec\n", time->seconds, time->nanoseconds);
  }

fail02:
  pbuf_free(p);

fail01:
  return length;
}

#endif

ssize_t ptpd_net_send_event(NetPath *net_path, const octet_t *buf, int16_t  length, TimeInternal *time)
{
#ifndef PTPD_POWER_PROFILE
  return ptpd_net_send(buf, length, time, &net_path->multicastAddr, net_path->eventPcb);
#else 
	// For Power Profile
	return ptpd_net_send(buf, length, time, net_path->multicastMac);
#endif
}

ssize_t ptpd_net_send_peer_event(NetPath *net_path, const octet_t *buf, int16_t  length, TimeInternal* time)
{
#ifndef PTPD_POWER_PROFILE
  return ptpd_net_send(buf, length, time, &net_path->peerMulticastAddr, net_path->eventPcb);
#else 
	// For Power Profile
	return ptpd_net_send(buf, length, time, net_path->peerMulticastMac);
#endif
}

ssize_t ptpd_net_send_general(NetPath *net_path, const octet_t *buf, int16_t  length)
{
#ifndef PTPD_POWER_PROFILE
  return ptpd_net_send(buf, length, NULL, &net_path->multicastAddr, net_path->generalPcb);
#else 
	// For Power Profile
	return ptpd_net_send(buf, length, NULL, net_path->multicastMac);
#endif
}

ssize_t ptpd_net_send_peer_general(NetPath *net_path, const octet_t *buf, int16_t  length)
{
#ifndef PTPD_POWER_PROFILE
  return ptpd_net_send(buf, length, NULL, &net_path->peerMulticastAddr, net_path->generalPcb);
#else 
	// For Power Profile
	return ptpd_net_send(buf, length, NULL, net_path->peerMulticastMac);
#endif
}

#endif
