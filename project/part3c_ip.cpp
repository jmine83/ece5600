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

octet my_mac[6];

// Choose one value for my_ip:
// octet my_ip[4] = { 192, 168, 1, 20 };
octet my_ip[4] = { 192, 168, 1, 10 };

// Choose one value for mac_target:
// octet mac_target[6] = { 0x00, 0x1A, 0xA0, 0xAC, 0xB0, 0xE8 }; // MAC address of 192.168.1.20
// octet mac_target[6] = { 0x00, 0x1A, 0xA0, 0xAC, 0xDF, 0x57 }; // MAC address of 192.168.1.10
octet mac_target[6] = { 0x00, 0x1C, 0x10, 0xF5, 0x0C, 0xAC }; // MAC address of 192.168.1.1

ether_frame frame;

octet IP_type[2] = { 0x08, 0x00 };
octet ARP_type[2] = { 0x08, 0x06 };

void ethernet_frame(octet dst_mac[6], octet src_mac[6], octet ether_type[2])
{
	// Destination MAC Address
	frame.dst_mac[0] = dst_mac[0];
	frame.dst_mac[1] = dst_mac[1];
	frame.dst_mac[2] = dst_mac[2];
	frame.dst_mac[3] = dst_mac[3];
	frame.dst_mac[4] = dst_mac[4];
	frame.dst_mac[5] = dst_mac[5];
	// Source MAC Address
	frame.src_mac[0] = src_mac[0];
	frame.src_mac[1] = src_mac[1];
	frame.src_mac[2] = src_mac[2];
	frame.src_mac[3] = src_mac[3];
	frame.src_mac[4] = src_mac[4];
	frame.src_mac[5] = src_mac[5];
	// Ethernet Type = 0x0800 for IP, 0x0806 for ARP
	frame.prot[0] = ether_type[0];
	frame.prot[1] = ether_type[1];
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

int ip_header_bytes = 20;
void chksum_ip_header()
{
	octet ip_header[ip_header_bytes];
	for (int i = 0; i < ip_header_bytes; i++)
		ip_header[i] = frame.data[i];
	int sum = chksum((octet *)ip_header,ip_header_bytes,0);
	frame.data[10] = ~sum >> 8;
	frame.data[11] = ~sum & 0xFF;
}

int data_bytes = 3;

octet src_ip[4];
octet dst_ip[4];
bool ip_data;
int ip_data_bytes;

void ip_frame()
{
	// IP Version = 0b0100**** for IPv4, 0b0110**** for IPv6
	// IP Header Length = 0b****0101 for no Options
	frame.data[0] = 0x45;
	// Type of Service
	frame.data[1] = 0x00;
	// Total Length = IP Header Length (20 bytes) + Data
	frame.data[2] = 0x00;
	frame.data[3] = 20 + ip_data_bytes;
	// Identification
	frame.data[4] = 0xFA;
	frame.data[5] = 0xCE;
	// Fragment Offset
	frame.data[6] = 0x00;
	frame.data[7] = 0x00;
	// Time to Live = 255 for max hops
	frame.data[8] = 0xFF;
	// Protocol = 1 for ICMP
	frame.data[9] = 0x01;
	// Header Checksum
	frame.data[10] = 0x00;
	frame.data[11] = 0x00;
	// Source IP Address
	frame.data[12] = src_ip[0];
	frame.data[13] = src_ip[1];
	frame.data[14] = src_ip[2];
	frame.data[15] = src_ip[3];
	// Destination IP Address
	frame.data[16] = dst_ip[0];
	frame.data[17] = dst_ip[1];
	frame.data[18] = dst_ip[2];
	frame.data[19] = dst_ip[3];
	chksum_ip_header();
}

int icmp_header_bytes = 8;
void chksum_icmp_header_data()
{
	int icmp_header_data_bytes = icmp_header_bytes + data_bytes;
	octet icmp_header_data[icmp_header_data_bytes];
	int I = ip_header_bytes + icmp_header_data_bytes;
	for (int i = ip_header_bytes; i < I; i++)
		icmp_header_data[i-ip_header_bytes] = frame.data[i];
	int sum = chksum((octet *)icmp_header_data,icmp_header_data_bytes,0);
	frame.data[22] = ~sum >> 8;
	frame.data[23] = ~sum & 0xFF;
}

int icmp_type;
octet icmp_identifier[2];
octet icmp_sequence_no[2];
bool icmp_data;
int icmp_data_bytes;

void icmp_frame()
{
	// Type = 8 for Request, 0 for Reply
	frame.data[20] = icmp_type;
	// Code
	frame.data[21] = 0x00;
	// Checksum
	frame.data[22] = 0x00;
	frame.data[23] = 0x00;
	// Identifier
	frame.data[24] = icmp_identifier[0];
	frame.data[25] = icmp_identifier[1];
	// Sequence No.
	frame.data[26] = icmp_sequence_no[0];
	frame.data[27] = icmp_sequence_no[1];
}

void print_ip_frame()
{
   printf("Source MAC Address = %02x:%02x:%02x:%02x:%02x:%02x\n", 
	  frame.src_mac[0],frame.src_mac[1],frame.src_mac[2],frame.src_mac[3],frame.src_mac[4],frame.src_mac[5]);
   printf("Source IP Address = %d.%d.%d.%d\n", 
	  frame.data[12],frame.data[13],frame.data[14],frame.data[15]);
   printf("Destination MAC Address = %02x:%02x:%02x:%02x:%02x:%02x\n",
	  frame.dst_mac[0],frame.dst_mac[1],frame.dst_mac[2],frame.dst_mac[3],frame.dst_mac[4],frame.dst_mac[5]);
   printf("Destination IP Address = %d.%d.%d.%d\n",
	  frame.data[16],frame.data[17],frame.data[18],frame.data[19]);
   printf("\n");
}

void print_icmp_frame()
{
   if ( icmp_type == 8 )
	  printf("Type = 8 (Request)\n");
   else if ( icmp_type == 0 )
	  printf("Type = 0 (Reply)\n");
   else
	  printf("Type = ERROR!\n");
   printf("Identifier = %02x %02x\n",icmp_identifier[0],icmp_identifier[1]);
   printf("Sequence No. = %02x %02x\n",icmp_sequence_no[0],icmp_sequence_no[1]);
   printf("\n");
   if ( icmp_data == true )
   {
		printf("ICMP Data = %02x:%02x:%02x\n", 
      		frame.data[28],frame.data[29],frame.data[30]);
		icmp_data = false;
   }
   printf("\n");
}

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
      if ( n < 42 + data_bytes ) continue; // bad frame!
      switch ( buf.prot[0]<<8 | buf.prot[1] )
      {
          case 0x800:
             ip_queue.send(PACKET,buf.data,n);
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
   int sent = 0;
   int sent_max = 4;
   bool icmp;
   
   /* buf_key
   00_0:3 = IP Version (0b0100_=IPv4 0b0110=IPv6)
   00_4:7 = IP Header Length
   01 = Type of Service
   02 to 03 = Total Length
   04 to 05 = Identification
   06 to 07 = Fragment Offset
   08 = Time to Live
   09 = Protocol (0x01=ICMP)
   10 to 11 = Header Checksum
   12 to 15 = Source IP Address
   16 to 19 = Destination IP Address
   20 to .. = IP Data
   20 = ICMP Type (8=Request 0=Reply)
   21 = ICMP Code
   22 to 23 = ICMP Checksum
   24 to 25 = ICMP Identifier
   26 to 27 = ICMP Sequence No.
   28 to .. = ICMP Data
   */

   my_mac[0] = net.get_mac()[0];
   my_mac[1] = net.get_mac()[1];
   my_mac[2] = net.get_mac()[2];
   my_mac[3] = net.get_mac()[3];
   my_mac[4] = net.get_mac()[4];
   my_mac[5] = net.get_mac()[5];
   
   while ( 1 )
   {
		ip_queue.recv(&event, buf, sizeof(buf));
		for (int ip_byte = 0; ip_byte < 42 + data_bytes; ip_byte++) /* Read first 42 IP bytes */
		{
			if ( ip_byte == 9 ) // Detect the protocol byte
			{
				if ( buf[ip_byte] == 1 ) // Is this ICMP?
				{
					printf("ICMP frame detected.\n\n");
					icmp = true; // Yes it is an ICMP.
				}
			}
		}
		if ( icmp == true )
		{
			printf("ICMP frame received.\n\n");
			icmp = false;
			// Is target IP address my IP address?
			if ( buf[16] == my_ip[0] && 
				 buf[17] == my_ip[1] && 
				 buf[18] == my_ip[2] && 
				 buf[19] == my_ip[3] )
			{
				// Set destination MAC address equal to target MAC address.
		 		// Set source MAC address equal to current machine's MAC address.
				ethernet_frame(mac_target,my_mac,IP_type);
				// Create the ICMP payload.
				//>> src_ip = my_ip
				src_ip[0] = my_ip[0];
				src_ip[1] = my_ip[1];
				src_ip[2] = my_ip[2];
				src_ip[3] = my_ip[3];
				//>> dst_ip = buf[12:15]
				dst_ip[0] = buf[12];
				dst_ip[1] = buf[13];
				dst_ip[2] = buf[14];
				dst_ip[3] = buf[15];
				ip_data = true;
				// ip_data_bytes = icmp_header_bytes (8) + data_bytes (3)
				ip_data_bytes = icmp_header_bytes + data_bytes;
				ip_frame();
				// icmp identifier = buf[24:25]
				icmp_identifier[0] = buf[24];
				icmp_identifier[1] = buf[25];
				// icmp_sequence_no = buf[26:27]
				icmp_sequence_no[0] = buf[26];
				icmp_sequence_no[1] = buf[27];
				icmp_data = true;
				icmp_data_bytes = data_bytes;
				if ( buf[20] == 8 ) // Is this an ICMP request? Then send ICMP reply.
				{
					printf("ICMP request has been received. Sending ICMP reply...\n\n");
					icmp_type = 0; // 0=Reply
					icmp_frame();
					frame.data[28] = 0xFE;
					frame.data[29] = 0xDC;
					frame.data[30] = 0xBA;
					chksum_icmp_header_data();
					print_ip_frame();
					print_icmp_frame();
					// Send the ethernet frame containing ICMP reply payload.
					net.send_frame(&frame,42 + data_bytes);
					printf("ICMP reply has been sent.\n\n");
					if ( sent != sent_max )
						sent++;
					else
						goto finish;
				}
				else if ( buf[20] == 0 ) // Is this an ICMP reply? Then send ICMP request.
				{
					icmp_sequence_no[1]++; // Increment ICMP sequence number.
					printf("ICMP reply has been received. Sending ICMP request...\n\n");
					icmp_type = 8; // 8=Request
					icmp_frame();
					frame.data[28] = 0xAB;
					frame.data[29] = 0xCD;
					frame.data[30] = 0xEF;
					chksum_icmp_header_data();
					print_ip_frame();
					print_icmp_frame();
					// Send the ethernet frame containing ICMP request payload.
					net.send_frame(&frame,42 + data_bytes);
					printf("ICMP request has been sent.\n\n");
					if ( sent != sent_max )
						sent++;
					else
						goto finish;
				}
				else
					printf("ICMP Type ERROR!\n\n");
			}
		}
   }
finish: printf("END\n");
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