/*
    * DESCRIPTION:
    * -----------
    *   A packet analyzer (also known as a packet sniffer) is a computer program or piece of computer hardware 
    *   that can intercept and log traffic that passes over a digital network or part of a network.
    *   Packet capture is the process of intercepting and logging traffic. 
    *   As Packet streams flow across the network, the sniffer captures each packet and, if needed, decodes the packet's raw Packet, 
    *   showing the values of various fields in the packet, and analyzes its content according to the appropriate RFC or other specifications.
    *
    * NOTE:
    * -----
    *   LSniffer (Low Level Sniffer) is a C scrIPt that allows you to sniffing all incoming and outgoing packets from the network. 
    *   It can capture and extract packets for Ethernet, ARP, IP, TCP, UDP, and ICMP protocol.
    *
    * ABOUT:
    * ------
    *   [AUTHOR]> Sha2ow_M4st3r
    *   [GITHUB]> https://github.com/Sha2ow-M4st3r
    *   [CONTACT]> Sha2ow[@]protonmail[.]com
*/

// Add required headers
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>

// For protocols structure
#include </usr/include/linux/if_ether.h>

#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>

#define ETH_P_ALL 0x0003
#define Buffer_LEN 65536
#define TRUE 1

struct arphdr { 
    u_short	ar_hrd;                 /* format of hardware address */ 
   	u_short	ar_pro;		            /* format of protocol address */
	u_char	ar_hln;		            /* length of hardware address */
	u_char	ar_pln;		            /* length of protocol address */
	u_short	ar_op;		            /* one of: */

    u_char Source_HDA[6];           /* Sender hardware address */ 
    u_char Source_IPA[4];           /* Sender IP address       */ 
    u_char Destination_HDA[6];      /* Target hardware address */ 
    u_char Destination_IPA[4];      /* Target IP address       */ 
}; 

// Global variables
int Raw_SOCKET;
int Ether_TYPE = 0;
int Protocol = 0;
// Store Layer 3 info
struct sockaddr Addr;

// Functions prototypes
void Create_SOCKET();
void Sniffer();
int Ethernet_EXTRACTION(char *);
void Address_Resolution_Protocol_EXTRACTION(int, char *);
int Internet_Protocol_EXTRACTION(int, char *);
void Internet_Control_Message_Protocol_EXTRACTION(int, int, char *);
void Transmission_Control_Protocol_EXTRACTION(int, int, char *);
void User_Packetgram_Protocol_EXTRACTION(int, int, char *);
void Display_INFO(int, char *);

int main()
{
    system("clear");
    Create_SOCKET();
    Sniffer();
    return 0;
}


// Create raw socket
void Create_SOCKET()
{
    /*
        * AF_PACKET = Thats basically packet level. (Only linux can support it) (Fuck windows :D)
        * 0x0003    = Every packet. (You can find it here: /usr/include/linux/if_Ethernet.h)
    */

    if ((Raw_SOCKET = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
    {
        fprintf(stderr, "[ERROR]. Could not create socket!\n");
        fprintf(stderr, "[REASON]. %s - (%d)\n", strerror(errno), errno);
        exit(0);
    }
}


// Reception of the network packet
void Sniffer()
{
    int Packets_BUFFER_SIZE;
    int Ethernet_SIZE = 0;
    int Internet_Protocol_SIZE = 0;

    socklen_t Addr_SIZE = sizeof(Addr);
    memset(&Addr, 0, sizeof(Addr));

    // Create buffer to store network packets
    unsigned char * Packets_BUFFER = (unsigned char *) malloc (Buffer_LEN);
    memset(Packets_BUFFER, 0, Buffer_LEN);

    if (!Packets_BUFFER)
    {
        fprintf(stderr, "[ERROR]. Could not create buffer to store network packets!\n");
        fprintf(stderr, "[REASON]. %s - (%d)\n", strerror(errno), errno);
        exit(0);
    }

    // Sniff all incoming and outgoing packets
    while (TRUE)
    {
        if ((Packets_BUFFER_SIZE = recvfrom(Raw_SOCKET, Packets_BUFFER, Buffer_LEN, 0, &Addr, &Addr_SIZE)) < 0)
            break;
        else
        {
            Ethernet_SIZE = Ethernet_EXTRACTION(Packets_BUFFER);

            if (Ether_TYPE == 8)
            {
                // IPv4
                Internet_Protocol_SIZE = Internet_Protocol_EXTRACTION(Ethernet_SIZE, Packets_BUFFER);
                if (Protocol == 1)
                    // ICMP
                    Internet_Control_Message_Protocol_EXTRACTION(Internet_Protocol_SIZE, Ethernet_SIZE, Packets_BUFFER);
                else if (Protocol == 6)
                    //TCP
                    Transmission_Control_Protocol_EXTRACTION(Internet_Protocol_SIZE, Ethernet_SIZE, Packets_BUFFER);
                else if (Protocol == 17)
                    //UDP
                    User_Packetgram_Protocol_EXTRACTION(Internet_Protocol_SIZE, Ethernet_SIZE, Packets_BUFFER);
                else
                    continue;
            }

            if (Ether_TYPE == 1544)
                // ARP
                Address_Resolution_Protocol_EXTRACTION(Ethernet_SIZE, Packets_BUFFER);

            
        }
    }

    // Close socket descriptor
    fprintf(stderr, "[ERROR]. Could not receive any packet!\n");
    fprintf(stderr, "[REASON]. %s - (%d)\n", strerror(errno), errno);
    close(Raw_SOCKET);
    exit(0);
}


// Ethernet header
int Ethernet_EXTRACTION(char * Packet)
{
    /*
    *    +------------------------------------------------------------------------+
    *    | Preamble | Destination MAC | Source MAC | Ether Type | User Data | FCS |
    *    +------------------------------------------------------------------------+
    *    |    8B    |       6B        |     6B     |     2B     | 46-1500B  | 4B  |
    *    +------------------------------------------------------------------------+
    */

    struct ethhdr * Ethernet = (struct ethhdr *)(Packet);
    int Ethernet_HEADER_SIZE = sizeof(struct ethhdr);

    printf("\nEthernetnet Header\n");
    printf("------------------\n");
    // %X: Number in base 16 with capital letters
    printf("|-Source MAC Address\t\t:\t%.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n", Ethernet->h_source[0], Ethernet->h_source[1], Ethernet->h_source[2], Ethernet->h_source[3], Ethernet->h_source[4], Ethernet->h_source[5]);
    printf("|-Destination MAC Address\t:\t%.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n", Ethernet->h_dest[0], Ethernet->h_dest[1], Ethernet->h_dest[2], Ethernet->h_dest[3], Ethernet->h_dest[4], Ethernet->h_dest[5]);
    
    switch (Ethernet->h_proto)
    {
        case 8 : printf("|-Ethernet-Type\t\t\t:\tInternet Protocol version 4 (0x%x)\n", (unsigned short) Ethernet->h_proto); Ether_TYPE = 8; break;
        case 1544 : printf("|-Ethernet-Type\t\t\t:\tAddress Resolution Protocol (0x%x)\n", (unsigned short) Ethernet->h_proto); Ether_TYPE = 1544; break;
        default : printf("|-Ethernet-Type\t\t\t:\tThe protocol is not defined! - (%d)\n", (unsigned short) Ethernet->h_proto); Ether_TYPE = 0;
    }

    return Ethernet_HEADER_SIZE;
}


// ARP header
void Address_Resolution_Protocol_EXTRACTION(int Ether_SIZE, char * Packet)
{
    /*
        * +----------------------------------------------------------------------------------------+
        * |                Hardware type                      |            Protocol type           |
        * +----------------------------------------------------------------------------------------+
        * | Hardware address length | Protocol address length |               Opcode               |
        * +----------------------------------------------------------------------------------------+
        * |                               Source hardware address                                  |
        * +----------------------------------------------------------------------------------------+
        * |                               Source protocol address                                  |
        * +----------------------------------------------------------------------------------------+
        * |                               Destination hardware address                             |
        * +----------------------------------------------------------------------------------------+
        * |                               Destination protocol address                             |
        * +----------------------------------------------------------------------------------------+
        * |                                         Data                                           |
        * +----------------------------------------------------------------------------------------+

        * Hardware type                  : 16
        * Protocol type                  : 16
        * Hardware address length        : 8
        * Protocol address length        : 8
        * Opcode                         : 16
        * Source hardware address        : 48
        * Source protocol address        : 32
        * Destination hardware address   : 48
        * Destination protocol address   : 32
    */

    struct arphdr * ARP = (struct arphdr *)(Packet + Ether_SIZE);
    char * Message = NULL;

    if ((unsigned short) ntohs(ARP->ar_op) == 1)
        Message = "REQUEST";
    else if ((unsigned short) ntohs(ARP->ar_op) == 2)
        Message = "REPLAY";
    else if ((unsigned short) ntohs(ARP->ar_op) == 0)
        Message = "RESERVED";
    else
        Message = "Unknown opcode!";

    int i;
    printf("\nAddress resolution protocol header\n");
    printf("------------------------------------\n");
    printf("  |-Hardware Type \t\t\t:\t%s\n", (unsigned short) (ntohs(ARP->ar_hrd) == 1) ? "Ethernet" : "Unknown type!"); 
    printf("  |-Protocol Type \t\t\t:\t%s\n", (unsigned short)(ntohs(ARP->ar_pro) == 2048) ? "IPv4" : "Unknown type!"); 
    printf("  |-Hardware Address Length\t\t:\t%d\n", ARP->ar_hln);
    printf("  |-Protocol Address Length\t\t:\t%d\n", ARP->ar_pln);
    printf("  |-Opcode\t\t\t\t:\t%s\n", Message); 
    printf("  |-Source Mac Address\t\t\t:\t%.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n", ARP->Source_HDA[0], ARP->Source_HDA[1], ARP->Source_HDA[2], ARP->Source_HDA[3], ARP->Source_HDA[4], ARP->Source_HDA[5]);
    printf("  |-Source IP Address\t\t\t:\t%d.%d.%d.%d\n", ARP->Source_IPA[0], ARP->Source_IPA[1], ARP->Source_IPA[2], ARP->Source_IPA[3]);
    printf("  |-Destination Mac Address\t\t:\t%.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n", ARP->Destination_HDA[0], ARP->Destination_HDA[1], ARP->Destination_HDA[2], ARP->Destination_HDA[3], ARP->Destination_HDA[4], ARP->Destination_HDA[5]);
    printf("  |-Destination IP Address\t\t:\t%d.%d.%d.%d\n", ARP->Destination_IPA[0], ARP->Destination_IPA[1], ARP->Destination_IPA[2], ARP->Destination_IPA[3]);
}


// IPv4 header
int Internet_Protocol_EXTRACTION(int Eth_SIZE, char * Packet)
{
    /*
    *     +-------------------------------------------------------------------------------------+
    *     | Version | IHL | Differentiated Services |              Total Length                 |
    *     +-------------------------------------------------------------------------------------+
    *     |            Identification               | Flags |        Fragment Offset            |
    *     +-------------------------------------------------------------------------------------+
    *     |        TTL           |     Protocol     |              Header checksum              |
    *     +-------------------------------------------------------------------------------------+
    *     |                                   Source IP Address                                 |  
    *     +-------------------------------------------------------------------------------------+
    *     |                                 Destination IP Address                              |
    *     +-------------------------------------------------------------------------------------+
    *     |                                   Options and padding                               |
    *     +-------------------------------------------------------------------------------------+

    * Version                   : 4
    * Internet Header Length    : 4
    * Differentiated Services   : 8
    * Total Length              : 16
    * Identification            : 16
    * Flags                     : 3
    * Fragment Offset           : 13
    * Time To Live              : 8
    * Protocol                  : 8
    * Header Checksum           : 16
    * Source IP Address         : 32
    * Destination IP Address    : 32
    */

    unsigned short IPHDRLEN;
    int Internet_protocol_HEADER_SIZE = sizeof(struct iphdr);
    struct iphdr * IP = (struct iphdr *)(Packet + Eth_SIZE);
    struct sockaddr_in Source_IP, Destionation_IP;
    memset(&Source_IP, 0, sizeof(Source_IP));
    memset(&Destionation_IP, 0, sizeof(Destionation_IP));

    Source_IP.sin_addr.s_addr = IP->saddr;
    Destionation_IP.sin_addr.s_addr = IP->daddr;
    IPHDRLEN = IP->ihl * 4;

    printf("\nInternet protocol version 4 Header\n");
    printf("----------------------------------\n");
    printf("  |-Version\t\t\t:\t%d\n",(unsigned int)IP->version);
	printf("  |-Internet Header Length\t:\t%d Bytes\n",((unsigned int)(IP->ihl))*4);
	printf("  |-Type Of Service\t\t:\t%d\n",(unsigned int)IP->tos);
	printf("  |-Total Length\t\t:\t%d Bytes\n",ntohs(IP->tot_len));
	printf("  |-Identification\t\t:\t%d\n",ntohs(IP->id));
	printf("  |-Offset\t\t\t:\t%d\n",IP->frag_off);
	printf("  |-Time To Live\t\t:\t%d\n",(unsigned int)IP->ttl);

    switch ((unsigned int) IP->protocol)
    {
        case 1 : printf("  |-Protocol\t\t\t:\tInternet Control Message Protocol (%d)\n", (unsigned int)IP->protocol); Protocol = 1; break;
        case 6 : printf("  |-Protocol\t\t\t:\tTransmission Control Protocol (%d)\n", (unsigned int)IP->protocol); Protocol = 6; break;
        case 17 : printf("  |-Protocol\t\t\t:\tUser Packetgram Protocol (%d)\n", (unsigned int)IP->protocol); Protocol = 17; break;
    }

	printf("  |-Header Checksum\t\t:\t%d\n",ntohs(IP->check));
	printf("  |-Source Address\t\t:\t%s\n", inet_ntoa(Source_IP.sin_addr));
	printf("  |-Destination Address\t\t:\t%s\n",inet_ntoa(Destionation_IP.sin_addr));
    return Internet_protocol_HEADER_SIZE;
}


// ICMP header
void Internet_Control_Message_Protocol_EXTRACTION(int IP_SIZE, int Ether_SIZE, char * Packet)
{
    /*
        * +------------------------------------------------+
        * |     Type     |     Code     |     Checksum     |
        * +------------------------------------------------+
        * |                      Data                      |
        * +------------------------------------------------+

        * Type       : 8
        * Code       : 8
        * Checksum   : 16
    */
    struct icmphdr * ICMP = (struct icmphdr *)(Packet + IP_SIZE + Ether_SIZE);
    unsigned int ICMP_TYPE = (ICMP->type);
    char * Message = NULL;

    if (ICMP_TYPE == 8)
        Message = "ECHO";
    else if (ICMP_TYPE == 0)
        Message = "REPLAY";
    else
        Message = "Unknown type";

    printf("\nInternet control message protocol Header\n");
    printf("----------------------------------------\n");
    printf("   |-Type\t\t\t:\t%s\n", Message);
    printf("   |-Code\t\t\t:\t%d\n", (unsigned int)(ICMP->code));
    printf("   |-Checksum\t\t\t:\t%d - (0x%x)\n", (unsigned int)(ICMP->checksum), (unsigned int)(ICMP->checksum));
}


// TCP header
void Transmission_Control_Protocol_EXTRACTION(int IP_SIZE, int Ether_SIZE, char * Packet)
{
    /*
        * 0                   1                   2                   3
        * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        * |          Source Port          |       Destination Port        |
        * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        * |                        Sequence Number                        |
        * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        * |                    Acknowledgment Number                      |
        * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        * |  Data |           |U|A|P|R|S|F|                               |
        * | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
        * |       |           |G|K|H|T|N|N|                               |
        * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        * |           Checksum            |         Urgent Pointer        |
        * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        * |                    Options                    |    Padding    |
        * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        * |                             data                              |
        * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        * Source Port               : 16
        * Destination Port          : 16
        * Sequence Number           : 32
        * Acknowledgment Number     : 32
        * Data Offset               : 4
        * Reserved                  : 3
        * Flags                     : 6 (Each one is a one bit)
        * Window                    : 16
        * Checksum                  : 16
        * Urgent Pointer            : 16
        * Options                   : 0-40

    */
    struct tcphdr * TCP = (struct tcphdr *)(Packet + IP_SIZE + Ether_SIZE);

    printf("\nTransmission control protocol header\n");
    printf("------------------------------------\n");
    printf("   |-Source Port\t\t\t:\t%u\n",ntohs(TCP->source));
    printf("   |-Destination Port\t\t\t:\t%u\n",ntohs(TCP->dest));
    printf("   |-Sequence Number\t\t\t:\t%u\n",ntohl(TCP->seq));
    printf("   |-Acknowledge Number\t\t\t:\t%u\n",ntohl(TCP->ack_seq));
    printf("   |-Header Length\t\t\t:\t%d BYTES\n" ,(unsigned int)TCP->doff*4);
    printf("    |-Urgent Flag\t\t\t:\t%d\n",(unsigned int)TCP->urg);
    printf("    |-Acknowledgement Flag\t\t:\t%d\n",(unsigned int)TCP->ack);
    printf("    |-Push Flag\t\t\t\t:\t%d\n",(unsigned int)TCP->psh);
    printf("    |-Reset Flag\t\t\t:\t%d\n",(unsigned int)TCP->rst);
    printf("    |-Synchronise Flag\t\t\t:\t%d\n",(unsigned int)TCP->syn);
    printf("   |-Finish Flag\t\t\t:\t%d\n",(unsigned int)TCP->fin);
    printf("   |-Window\t\t\t\t:\t%d\n",ntohs(TCP->window));
    printf("   |-Checksum\t\t\t\t:\t%d\n",ntohs(TCP->check));
    printf("   |-Urgent Pointer\t\t\t:\t%d\n",TCP->urg_ptr);
}


// UDP header
void User_Packetgram_Protocol_EXTRACTION(int IP_SIZE, int Ether_SIZE, char * Packet)
{
    /*
        * +--------------------------------------------------+
        * |       Source Port     |     Destination Port     |
        * +--------------------------------------------------+
        * |         Length        |         Checksum         |
        * +--------------------------------------------------+
        * |                      Data                        |
        * +--------------------------------------------------+

        * Source Port        : 16
        * Destination Port   : 16
        * Length             : 16
        * Checksum           : 16
    */
    struct udphdr * UDP = (struct udphdr *)(Packet + IP_SIZE + Ether_SIZE);
    printf("\nUser Packetgram protocol header\n");
    printf("-------------------------------\n");
	printf("   |-Source portt\t\t:\t%d\n", ntohs(UDP->uh_sport));
	printf("   |-Destination portt\t\t:\t%d\n", ntohs(UDP->uh_dport));
	printf("   |-Lengtht\t\t\t:\t%d\n", ntohs(UDP->uh_ulen));
	printf("   |-Checksumt\t\t\t:\t%d - (0x%x)\n", ntohs(UDP->uh_sum), ntohs(UDP->uh_sum));
}