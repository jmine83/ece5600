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

octet my_ip[4] = { 192, 168, 1, 20 };

ether_frame frame;
octet opcode[2];
octet sender_mac[6];
octet sender_ip[4];
octet target_mac[6];
octet target_ip[4];

void arp_frame()
{
	//// Hardware Type = 0x0001 for Ethernet
	frame.data[0] = 0x00;
	frame.data[1] = 0x01;
	//// Protocol Type = 0x0800 for IPv4, 0x86DD for IPv6
	frame.data[2] = 0x08;
	frame.data[3] = 0x00;
	//// Hardware Size = 6 for Ethernet
	frame.data[4] = 6;
	//// Protocol Size = 4 for IPv4, 16 for IPv6
	frame.data[5] = 4;
	//// Opcode = 1 for Request, 2 for Reply
	frame.data[6] = opcode[0];
	frame.data[7] = opcode[1];
	//// Sender's MAC Address
	frame.data[8] = sender_mac[0];
	frame.data[9] = sender_mac[1];
	frame.data[10] = sender_mac[2];
	frame.data[11] = sender_mac[3];
	frame.data[12] = sender_mac[4];
	frame.data[13] = sender_mac[5];
	//// Sender's IP Address
	frame.data[14] = sender_ip[0];
	frame.data[15] = sender_ip[1];
	frame.data[16] = sender_ip[2];
	frame.data[17] = sender_ip[3];
	//// Target MAC Address
	frame.data[18] = target_mac[0];
	frame.data[19] = target_mac[1];
	frame.data[20] = target_mac[2];
	frame.data[21] = target_mac[3];
	frame.data[22] = target_mac[4];
	frame.data[23] = target_mac[5];
	//// Target IP Address
	frame.data[24] = target_ip[0];
	frame.data[25] = target_ip[1];
	frame.data[26] = target_ip[2];
	frame.data[27] = target_ip[3];
}

void print_frame()
{
   printf("Sender's MAC Address = %02x:%02x:%02x:%02x:%02x:%02x\n", 
      sender_mac[0],sender_mac[1],sender_mac[2],sender_mac[3],sender_mac[4],sender_mac[5]);
   printf("Sender's IP Address = %d.%d.%d.%d\n", 
	  sender_ip[0],sender_ip[1],sender_ip[2],sender_ip[3]);
   printf("Target MAC Address = %02x:%02x:%02x:%02x:%02x:%02x\n",
	  target_mac[0],target_mac[1],target_mac[2],target_mac[3],target_mac[4],target_mac[5]);
   printf("Target IP Address = %d.%d.%d.%d\n",
	  target_ip[0],target_ip[1],target_ip[2],target_ip[3]);
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

// Toy function to print something interesting when an ARP frame arrives
//
void *arp_protocol_loop(void *arg)
{
   octet buf[1500];
   event_kind event;
   bool request;
   bool reply;

   /* buf_key
   00 to 01 = Hardware Type (0x0001=Ethernet)
   02 to 03 = Protocol Type (0x0800=IPv4 0x86DD=IPv6)
   04 = Hardware Size (6=Ethernet)
   05 = Protocol Size (4=IPv4 16=IPv6)
   06 to 07 = Opcode (1=Request 2=Reply)
   08 to 13 = Sender's MAC Address
   14 to 17 = Sender's IP Address
   18 to 23 = Target MAC Address
   24 to 27 = Target IP Address
   28 to .. = Data
   */

   while ( 1 )
   {
      arp_queue.recv(&event, buf, sizeof(buf));
      for (int arp_byte = 0; arp_byte < 42; arp_byte++) // Read first 42 bytes
      {
         if ( arp_byte == 7 ) // Detect the opcode byte
         {
            if ( buf[arp_byte] == 1 ) // Is this a request?
            {
               printf("ARP request detected.\n\n");
	           request = true; // Yes it is a request.
            }
            else if ( buf[arp_byte] == 2 ) // Is this a reply?
	        {
	           printf("ARP reply detected.\n\n");
			   reply = true; // Yes it is a reply.
	        }
			else
			   printf("Opcode ERROR!\n\n");
         }
         if ( arp_byte == 24 ) // Detect the target IP address
         {
            printf("Target IP address detected.\n\n");
			if ( request == true ) // Send ARP reply to ARP request
			{
				printf("ARP request received.\n\n");
				request = false;
				// Is target IP address my IP address?
				if ( buf[24] == my_ip[0] && 
					buf[25] == my_ip[1] && 
					buf[26] == my_ip[2] && 
					buf[27] == my_ip[3] )
				{
					printf("Target IP address matches.\n\n");
					// Create and send the ethernet frame containing ARP reply payload.
					printf("Creating ethernet frame containing ARP reply payload...\n\n");
					//// Set ARP reply destination MAC address equal to ARP sender's MAC address.
					//// buf_key: 08 to 13 = Sender's MAC Address
					//>> frame.dst_mac = buf[8:13]
					frame.dst_mac[0] = buf[8];
					frame.dst_mac[1] = buf[9];
					frame.dst_mac[2] = buf[10];
					frame.dst_mac[3] = buf[11];
					frame.dst_mac[4] = buf[12];
					frame.dst_mac[5] = buf[13];
					//// Set ARP reply source MAC address equal to current machine's MAC address.
					//>> frame.src_mac = net.get_mac()
					frame.src_mac[0] = net.get_mac()[0];
					frame.src_mac[1] = net.get_mac()[1];
					frame.src_mac[2] = net.get_mac()[2];
					frame.src_mac[3] = net.get_mac()[3];
					frame.src_mac[4] = net.get_mac()[4];
					frame.src_mac[5] = net.get_mac()[5];
					//>> frame.prot = { 0x08, 0x06 }
					frame.prot[0] = 0x08;
					frame.prot[1] = 0x06;
					//// Create the ARP reply payload.
					opcode[0] = 0;
					opcode[1] = 2; // 2=Reply
					//>> sender_mac = frame.src_mac
					sender_mac[0] = frame.src_mac[0];
					sender_mac[1] = frame.src_mac[1];
					sender_mac[2] = frame.src_mac[2];
					sender_mac[3] = frame.src_mac[3];
					sender_mac[4] = frame.src_mac[4];
					sender_mac[5] = frame.src_mac[5];
					//// buf_key: 24 to 27 = Target IP Address
					//>> sender_ip = buf[24:27]
					sender_ip[0] = buf[24];
					sender_ip[1] = buf[25];
					sender_ip[2] = buf[26];
					sender_ip[3] = buf[27];
					//>> target_mac = frame.dst_mac
					target_mac[0] = frame.dst_mac[0];
					target_mac[1] = frame.dst_mac[1];
					target_mac[2] = frame.dst_mac[2];
					target_mac[3] = frame.dst_mac[3];
					target_mac[4] = frame.dst_mac[4];
					target_mac[5] = frame.dst_mac[5];
					//// buf_key: 14 to 17 = Sender's IP Address
					//>> target_ip = buf[14:17]
					target_ip[0] = buf[14];
					target_ip[1] = buf[15];
					target_ip[2] = buf[16];
					target_ip[3] = buf[17];
					arp_frame();
					print_frame();
					// Send the ethernet frame containing ARP reply payload.
					net.send_frame(&frame,42);
					printf("ARP reply has been sent. END\n\n");
				}
			}
			else
			{
				printf("ARP reply received. END\n\n");
				reply = false;
			}
         }
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
   for ( ; ; )
      sleep(1);
}