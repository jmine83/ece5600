#include "frameio.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

frameio net;             // gives us access to the raw network
message_queue ip_queue;  // message queue for the IP protocol stack

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
      }
   }
}

int chksum(octet *s, int bytes, int initial)
{
   long sum = initial;
   int i;
   for ( i=0; i<bytes-1; i+=2 )
   {
      sum += s[i]*256 + s[i+1];
   }
   //
   // handle the odd byte
   //
   if ( i < bytes ) sum += s[i]*256;
   //
   // wrap carries back into sum
   //
   while ( sum > 0xffff ) sum = (sum & 0xffff) + (sum >> 16);
   return sum;
}

//
// Toy function to print something interesting when an IP frame arrives
//
void *ip_protocol_loop(void *arg)
{
   octet buf[1500];
   event_kind event;
   octet chksum_in[2];
   octet chksum_out[2];
   bool chksum_pass;
   octet my_ip[4] = { 192, 168, 1, 20 };
   int ip_header_bytes = 20;
   
   /* buf_key
   00_0:3 = Version (0b0100_=IPv4 0b0110=IPv6)
   00_4:7 = Internet Header Length
   01 = Differentiated Services
   02 to 03 = Total Length
   04 to 05 = Identification
   06 to 07 = Fragment Offset
   08 = Time to Live
   09 = Protocol (0x01=ICMP)
   10 to 11 = Header Checksum
   12 to 15 = Source IP Address
   16 to 19 = Destination IP Address
   20 to .. = Data
   */

   while ( 1 )
   {
      ip_queue.recv(&event, buf, sizeof(buf));
      for ( int ip_byte = 0; ip_byte < 42; ip_byte++) /* Read first 42 IP bytes */
      {
		// Is destination IP address my IP address?
		// Is frame received of type ICMP?
		if ( buf[16] == my_ip[0] && 
			buf[17] == my_ip[1] && 
			buf[18] == my_ip[2] && 
			buf[19] == my_ip[3] && 
			buf[9] == 1)
		{
			printf("ICMP frame to my IP address received.\n\n");
			chksum_in[0] = buf[10]; chksum_in[1] = buf[11]; // Save incoming IP frame checksum
			printf("IP header checksum received is %02x %02x.\n\n",chksum_in[0],chksum_in[1]);
			buf[10] = 0; buf[11] = 0; // Clear checksum of IP frame received
			octet ip_header[ip_header_bytes];
			for (int i = 0; i < ip_header_bytes; i++)
				ip_header[i] = buf[i];
			int sum = chksum((octet *)ip_header,ip_header_bytes,0);
			chksum_out[0] = ~sum >> 8;
			chksum_out[1] = ~sum & 0xFF;
			printf("IP header checksum calculated is %02x %02x.\n\n",chksum_out[0],chksum_out[1]);
			// Is the IP header checksum correct?
			if ( chksum_in[0] == chksum_out[0] && chksum_in[1] == chksum_out[1] )
			{
				printf("IP header checksum passed.\n\n");
				chksum_pass = true;
			}
			else
			{
				printf("IP header checksum failed.\n\n");
				chksum_pass = false;
			}
			goto finish;
		}	     
      }
   }
finish:;
}

//
// if you're going to have pthreads, you'll need some thread descriptors
//
pthread_t loop_thread, ip_thread;

//
// start all the threads then step back and watch (actually, the timer
// thread will be started later, but that is invisible to us.)
//
int main()
{
   net.open_net("enp3s0");
   pthread_create(&loop_thread,NULL,protocol_loop,NULL);
   pthread_create(&ip_thread,NULL,ip_protocol_loop,NULL);
   for ( ; ; )
      sleep(1);
}