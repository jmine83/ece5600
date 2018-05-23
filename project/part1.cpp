#include "frameio.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

frameio net;             // gives us access to the raw network
message_queue ip_queue;  // message queue for the IP protocol stack
message_queue arp_queue; // message queue for the ARP protocol stack

struct ether_frame       // handy template for 802.3/DIX frames
{
   octet dst_mac[6];     // destination MAC address
   octet src_mac[6];     // source MAC address
   octet prot[2];        // protocol (or length)
   octet data[1500];     // payload
};

//
// This thread sits around and receives frames from the network.
// When it gets one, it dispatches it to the proper protocol stack.
//
void *protocol_loop(void *arg)
{
   ether_frame buf;
   while(1)
   {
      int n = net.recv_frame(&buf,sizeof(buf));
      if ( n < 42 ) continue; // bad frame!
      switch ( buf.prot[0]<<8 | buf.prot[1] )
      {
          case 0x800:
             ip_queue.send(PACKET,buf.data,n);
             break;
          case 0x806:
             arp_queue.send(PACKET,buf.data,n);
             break;
      }
   }
}

//
// Toy function to print something interesting when an IP frame arrives
//
void *ip_protocol_loop(void *arg)
{
   octet buf[1500];
   event_kind event;
   int ip_byte = 0;

   while ( 1 )
   {
      ip_queue.recv(&event, buf, sizeof(buf));
	  printf("IP detected.\n");
      for ( ip_byte = 0; ip_byte < 42; ip_byte++) /* Read first 42 IP bytes */
      {
	     printf("%02x ",buf[ip_byte]); /* Print IP byte */
	     if ( ip_byte == 21 || ip_byte == 41 )
	        printf("\n"); /* Add new line for the 22nd and 42nd IP byte. */
      }
   }
}

//
// Toy function to print something interesting when an ARP frame arrives
//
void *arp_protocol_loop(void *arg)
{
   octet buf[1500];
   event_kind event;
   int arp_byte = 0;

   while ( 1 )
   {
      arp_queue.recv(&event, buf, sizeof(buf));
      printf("ARP detected.\n");
	  for ( arp_byte = 0; arp_byte < 42; arp_byte++) /* Read first 42 ARP bytes */
      {
	     printf("%02x ",buf[arp_byte]); /* Print ARP byte */
	     if ( arp_byte == 21 || arp_byte == 41 )
	        printf("\n"); /* Add new line for the 22nd and 42nd ARP byte. */
      }
   }
}

//
// if you're going to have pthreads, you'll need some thread descriptors
//
pthread_t loop_thread, arp_thread, ip_thread;

//
// start all the threads then step back and watch (actually, the timer
// thread will be started later, but that is invisible to us.)
//
int main()
{
   net.open_net("enp3s0"); // Ethernet port of lab room computer.
   pthread_create(&loop_thread,NULL,protocol_loop,NULL);
   pthread_create(&arp_thread,NULL,arp_protocol_loop,NULL);
   pthread_create(&ip_thread,NULL,ip_protocol_loop,NULL);
   for ( ; ; )
      sleep(1);
}