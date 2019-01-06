#! /usr/bin/python

# Importing the requirement modules
import subprocess
import binascii
import platform
import struct
import socket
import time
import sys
import os

from termcolor import colored
from prettytable import PrettyTable

# Global variables
Time = time.asctime(time.localtime(time.time()))


# First of all, we need to make sure that the PSniffer runs on the linux operating system
if "Linux" not in platform.platform():
    print colored("[ERROR]>", "red", attrs=["bold"]), colored("Sorry, PSniffer only work on linux platform.")
    sys.exit()

# Make sure that the PSniffer is executed in root mode
if os.getuid() != 0:
    print colored("[ERROR]>", "red", attrs=["bold"]), colored("Sorry, you must run me in root permission.", "white", attrs=["bold"])
    sys.exit()



# Clear display
def Clear_terminal():
    subprocess.call("clear", shell=True)



# Banner
def Display():
    print colored("[Coded-by]>", "yellow", attrs=["bold"]), colored("Sha2ow_M4st3r", "white", attrs=["bold"])
    print colored("[Contact]>", "yellow", attrs=["bold"]), colored("Sha2ow@protonmail.com", "white", attrs=["bold"])
    print colored("[Github]>", "yellow", attrs=["bold"]), colored("https://github.com/Sha2ow-M4st3r", "white", attrs=["bold"])  
    


# Create a raw socket
def Raw_socket():
    try:
        global RAWS
        # AF_PACKET = Thats basically packet level. (Only linux can support it) (Fuck windows :D)
        # 0x0003    = Every packet. (You can find it here: /usr/include/linux/if_ether.h)
        RAWS = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    except socket.error as MSG:
        print colored("[ERROR]>", "red", attrs=["bold"]), colored("Socket creation error: " + str(MSG), "white", attrs=["bold"])
        Display()
        sys.exit()



# Sniffer
def Packet_sniffer():
    try:
        global Packet
	global Total_Packets
	Total_Packets = 0

        # Receive packets
        while True:
            Recv = RAWS.recvfrom(65565)
            # Receive all of them
            Packet = Recv[0]
            Total_Packets += 1
            Ethernet()
    except socket.error as MSG:
        print colored("\n[ERROR]>", "red", attrs=["bold"]), colored("Failed to receive packets: " + str(MSG), "white", attrs=["bold"])
	print colored("[Total Packets]>", "magenta", attrs=["bold"]), colored(Total_Packets, "white", attrs=["bold"])
        Display()
        sys.exit()
    except KeyboardInterrupt:
        print colored("\n[ERROR]>", "red", attrs=["bold"]), colored("Script stopped: Kill signal (CTRL+C)", "white", attrs=["bold"])
	print colored("[Total Packets]>", "magenta", attrs=["bold"]), colored(Total_Packets, "white", attrs=["bold"])
        Display()
        sys.exit()



# Decapsulate Ethernet frame
def Ethernet():

    # +------------------------------------------------------------------------+
    # | Preamble | Destination MAC | Source MAC | Ether Type | User Data | FCS |
    # +------------------------------------------------------------------------+
    # |    8B    |       6B        |     6B     |     2B     | 46-1500B  | 4B  |
    # +------------------------------------------------------------------------+

    # EtherType values for some notable protocols (From wikipedia)
    Protocols_Number = {
    0x0800: "Internet Protocol version 4 (IPv4)",
    0x0806: "Address Resolution Protocol (ARP)",
    0x0842: "Wake-on-LAN[9]",
    0x22f3: "IETF TRILL Protocol",
    0x22ea: "Stream Reservation Protocol",
    0x6003: "DECnet Phase IV",
    0x8035: "Reverse Address Resolution Protocol",
    0x809B: "AppleTalk (Ethertalk)",
    0x80f3: "AppleTalk Address Resolution Protocol (AARP)",
    0x8100: "VLAN-tagged frame (IEEE 802.1Q) and Shortest Path Bridging IEEE 802.1aq with NNI compatibility[10]",
    0x8137: "IPX",
    0x8204: "QNX Qnet",
    0x86dd: "Internet Protocol Version 6 (IPv6)",
    0x8808: "Ethernet flow control",
    0x8809: "Ethernet Slow Protocols[11] such as the Link Aggregation Control Protocol",
    0x8819: "CobraNet",
    0x8847: "MPLS unicast",
    0x8848: "MPLS multicast",
    0x8863: "PPPoE Discovery Stage",
    0x8864: "PPPoE Session Stage",
    0x886d: "Intel Advanced Networking Services [12]",
    0x8870: "Jumbo Frames (Obsoleted draft-ietf-isis-ext-eth-01)",
    0x887b: "HomePlug 1.0 MME",
    0x888e: "EAP over LAN (IEEE 802.1X)",
    0x8892: "PROFINET Protocol",
    0x889a: "HyperSCSI (SCSI over Ethernet)",
    0x88a2: "ATA over Ethernet",
    0x88a4: "EtherCAT Protocol",
    0x88a8: "Provider Bridging (IEEE 802.1ad) & Shortest Path Bridging IEEE 802.1aq[10]",
    0x88ab: "Ethernet Powerlink[citation needed]",
    0x88b8: "GOOSE (Generic Object Oriented Substation event)",
    0x88b9: "GSE (Generic Substation Events) Management Services",
    0x88ba: "SV (Sampled Value Transmission)",
    0x88cc: "Link Layer Discovery Protocol (LLDP)",
    0x88cd: "SERCOS III",
    0x88dc: "WSMP, WAVE Short Message Protocol",
    0x88e1: "HomePlug AV MME[citation needed]",
    0x88e3: "Media Redundancy Protocol (IEC62439-2)",
    0x88e5: "MAC security (IEEE 802.1AE)",
    0x88e7: "Provider Backbone Bridges (PBB) (IEEE 802.1ah)",
    0x88f7: "Precision Time Protocol (PTP) over Ethernet (IEEE 1588)",
    0x88f8: "NC-SI",
    0x88fB: "Parallel Redundancy Protocol (PRP)",
    0x8902: "IEEE 802.1ag Connectivity Fault Management (CFM) Protocol / ITU-T Recommendation Y.1731 (OAM)",
    0x8906: "Fibre Channel over Ethernet (FCoE)",
    0x8914: "FCoE Initialization Protocol",
    0x8915: "RDMA over Converged Ethernet (RoCE)",
    0x891d: "TTEthernet Protocol Control Frame (TTE)",
    0x892f: "High-availability Seamless Redundancy (HSR)",
    0x9000: "Ethernet Configuration Testing Protocol[13]",
    0x9100: "VLAN-tagged (IEEE 802.1Q) frame with double tagging"
}

    try:
        # We do not need Preamble and UserData for sniffing. (6+6+2=14)
        Ethernet_Length = 14
        Ethernet_Header = Packet[:Ethernet_Length]
        Ethernet_Unpack = struct.unpack("!6s6sH", Ethernet_Header)
    except:
        print colored("[[Ethernet-Header]]>", "red", attrs=["bold"]), colored("Extraction failed", "white", attrs=["bold"])
	print colored("[Total Packets]>", "magenta", attrs=["bold"]), colored(Total_Packets, "white", attrs=["bold"])
        Display()
        sys.exit()

    # Extraction
    Destination_MAC = Ethernet_Unpack[0]
    Source_MAC = Ethernet_Unpack[1]
    Ether_Type = Ethernet_Unpack[2]
    
    if Ether_Type in Protocols_Number:
        Ether_Type_Protocol = Protocols_Number[Ether_Type]
    else:
        Ether_Type_Protocol = "Not define"

    # Translate MAC Address to human readable
    DstMAC = ":".join("%02x" % ord(y) for y in Destination_MAC).upper()
    SrcMAC = ":".join("%02x" % ord(x) for x in Source_MAC).upper()

    # Broadcast
    if DstMAC == "ff:ff:ff:ff:ff:ff":
        DstMAC = "ff:ff:ff:ff:ff:ff"

    print colored("[Ethernet]", "green", attrs=["bold"])  
    print colored("----------", "green", attrs=["bold"])    
    print colored("Destination MAC\t\t\t\t", "green", attrs=["bold"]), colored(":", "green", attrs=["bold"]), colored(DstMAC, "white", attrs=["bold"])
    print colored("Source MAC\t\t\t\t", "green", attrs=["bold"]), colored(":", "green", attrs=["bold"]), colored(SrcMAC, "white", attrs=["bold"])
    print colored("Ether Type\t\t\t\t", "green", attrs=["bold"]), colored(":", "green", attrs=["bold"]),colored(hex(Ether_Type), "white", attrs=["bold"])
    print colored("Protocol\t\t\t\t", "green", attrs=["bold"]), colored(":", "green", attrs=["bold"]), colored(Ether_Type_Protocol, "white", attrs=["bold"])
    print "\n"

    # Checking EtherType field
    if Ether_Type == 2054:
        ARP()
    if Ether_Type == 2048:
        IP()
    


# Decapsulate Address Resolution Protocol frame
def ARP():      

    # +----------------------------------------------------------------------------------------+
    # |                Hardware type                      |            Protocol type           |
    # +----------------------------------------------------------------------------------------+
    # | Hardware address length | Protocol address length |               Opcode               |
    # +----------------------------------------------------------------------------------------+
    # |                               Source hardware address                                  |
    # +----------------------------------------------------------------------------------------+
    # |                               Source protocol address                                  |
    # +----------------------------------------------------------------------------------------+
    # |                               Destination hardware address                             |
    # +----------------------------------------------------------------------------------------+
    # |                               Destination protocol address                             |
    # +----------------------------------------------------------------------------------------+
    # |                                         Data                                           |
    # +----------------------------------------------------------------------------------------+

    # Hardware type                  : 16
    # Protocol type                  : 16
    # Hardware address length        : 8
    # Protocol address length        : 8
    # Opcode                         : 16
    # Source hardware address        : 48
    # Source protocol address        : 32
    # Destination hardware address   : 48
    # Destination protocol address   : 32

    # Hardware type
    HardWareType = {
        0:	"reserved",
        1:	"Ethernet",	
        2:	"Experimental Ethernet",
        3:	"Amateur Radio AX.25",
        4:	"Proteon ProNET Token Ring",	 
        5:	"Chaos",
        6:	"IEEE 802",	 
        7:	"ARCNET",
        8:	"Hyperchannel:",	 
        9:	"Lanstar",
        10:	"Autonet Short Address",	 
        11:	"LocalTalk",
        12:	"LocalNet (IBM PCNet or SYTEK LocalNET)",	 
        13:	"Ultra link",
        14:	"SMDS",
        15:	"Frame Relay",	 
        16:	"ATM, Asynchronous Transmission Mode",	 
        17:	"HDLC",
        18:	"Fibre Channel",
        19:	"ATM, Asynchronous Transmission Mode",
        20:	"Serial Line",
        21:	"ATM, Asynchronous Transmission Mode",	 
        22:	"MIL-STD-188-220",
        23:	"Metricom",
        24:	"IEEE 1394.1995",	 
        25:	"MAPOS",
        26:	"Twinaxial",	 
        27:	"EUI-64",
        28:	"HIPARP",
        29:	"IP and ARP over ISO 7816-3",	 
        30:	"ARPSec",
        31:	"IPsec tunnel",
        32:	"Infiniband",
        33:	"CAI, TIA-102 Project 25 Common Air Interface",	 
        34:	"Wiegand Interface",
        35:	"Pure IP",
        36:	"HW_EXP1", 	 
        256: "HW_EXP2"
    }

    # Opcode
    OpcodeType = {
        0: "reserved",
        1: "Request",
        2: "Reply",
        3: "Request Reverse",
        4: "Reply Reverse",
        5: "DRARP Request",
        6: "DRARP Reply",
        7: "DRARP Error",
        8: "InARP Request",
        9: "InARP Reply",
        10: "ARP NAK",
        11: "MARS Request",
        12:	"MARS Multi",
        13:	"MARS MServ", 
        14:	"MARS Join", 
        15:	"MARS Leave",	 
        16:	"MARS NAK", 
        17:	"MARS Unserv",	 
        18:	"MARS SJoin",
        19:	"MARS SLeave",	 
        20:	"MARS Grouplist Request",	 
        21:	"MARS Grouplist Reply", 
        22:	"MARS Redirect Map",
        23:	"MAPOS UNARP",
        24:	"OP_EXP1",
        25:	"OP_EXP2"
        }

    #Arp_Length = 28 
    Arp_Header = Packet[14:42]
    Arp_Unpack = struct.unpack("!HHBBH6s4s6s4s", Arp_Header)

    # Extraction
    HardwareType = Arp_Unpack[0]
    ProtocolType = Arp_Unpack[1]
    HardwareAddressLength = Arp_Unpack[2]
    ProtocolAddressLength = Arp_Unpack[3]
    Opcode = Arp_Unpack[4]
    SourceMAC = Arp_Unpack[5].encode("hex")
    SourceIP = socket.inet_ntoa(Arp_Unpack[6])
    DestinationMAC = Arp_Unpack[7].encode("hex")
    DestinationIP = socket.inet_ntoa(Arp_Unpack[8])

    
    if HardwareType in HardWareType:
        HardwareType_Name = HardWareType[HardwareType]
    else:
        HardwareType_Name = "Not define"

    if ProtocolType == 2048:
       ProtocolType = "0x0800 (IPv4)"
    else:
        ProtocolType = "Not define"

    if Opcode in OpcodeType:
        Opcode = OpcodeType[Opcode]
    else:
        Opcode = "Not define"

    
    # Translate MAC AND IP address to human readable
    SrcMAC = ""
    DstMAC = ""

    for C in range(0, len(SourceMAC) - 1, 2):
        SrcMAC += SourceMAC[C:C+2] + ":"

    for C in range(0, len(DestinationMAC) - 1, 2):
        DstMAC += DestinationMAC[C:C+2] + ":"  

    print colored("[Address Resolution Protocol]", "cyan", attrs=["bold"])
    print colored("-----------------------------", "cyan", attrs=["bold"])
    print colored("Hardware Type\t\t\t\t", "cyan", attrs=["bold"]), colored(":", "cyan", attrs=["bold"]), colored(HardwareType_Name, "cyan", attrs=["bold"])
    print colored("Protocol Type\t\t\t\t", "cyan", attrs=["bold"]), colored(":", "cyan", attrs=["bold"]), colored(ProtocolType, "cyan", attrs=["bold"])
    print colored("Hardware Address Length\t\t\t", "cyan", attrs=["bold"]), colored(":", "cyan", attrs=["bold"]), colored(HardwareAddressLength, "cyan", attrs=["bold"])
    print colored("Protocol Address Length\t\t\t", "cyan", attrs=["bold"]), colored(":", "cyan", attrs=["bold"]), colored(ProtocolAddressLength, "cyan", attrs=["bold"])
    print colored("Opcode\t\t\t\t\t", "cyan", attrs=["bold"]), colored(":", "cyan", attrs=["bold"]), colored(Opcode, "cyan", attrs=["bold"])
    print colored("Source Protocol Address\t\t\t", "cyan", attrs=["bold"]), colored(":", "cyan", attrs=["bold"]), colored(SourceIP, "cyan", attrs=["bold"])
    print colored("Source Hardware Address\t\t\t", "cyan", attrs=["bold"]), colored(":", "cyan", attrs=["bold"]), colored(SrcMAC[:17].upper(), "cyan", attrs=["bold"])
    print colored("Destination Hardware Address\t\t", "cyan", attrs=["bold"]), colored(":", "cyan", attrs=["bold"]), colored(DstMAC[:17].upper(), "cyan", attrs=["bold"])
    print colored("Destination Protocol Address\t\t", "cyan", attrs=["bold"]), colored(":", "cyan", attrs=["bold"]), colored(DestinationIP, "cyan", attrs=["bold"])
    print "\n"



# Decapsulate Internet Protocol packet
def IP():

    # +-------------------------------------------------------------------------------------+
    # | Version | IHL | Differentiated Services |              Total Length                 |
    # +-------------------------------------------------------------------------------------+
    # |            Identification               | Flags |        Fragment Offset            |
    # +-------------------------------------------------------------------------------------+
    # |        TTL           |     Protocol     |              Header checksum              |
    # +-------------------------------------------------------------------------------------+
    # |                                   Source IP Address                                 |  
    # +-------------------------------------------------------------------------------------+
    # |                                 Destination IP Address                              |
    # +-------------------------------------------------------------------------------------+
    # |                                   Options and padding                               |
    # +-------------------------------------------------------------------------------------+

    # Version                   : 4
    # Internet Header Length    : 4
    # Differentiated Services   : 8
    # Total Length              : 16
    # Identification            : 16
    # Flags                     : 3
    # Fragment Offset           : 13
    # Time To Live              : 8
    # Protocol                  : 8
    # Header Checksum           : 16
    # Source IP Address         : 32
    # Destination IP Address    : 32

    Protocols_Name = {
        0: "HOPOPT, IPv6 Hop-by-Hop Option",
        1:	"ICMP, Internet Control Message Protocol",
        3:	"GGP, Gateway to Gateway Protocol",
        4:	"IP in IP encapsulation",
        5:	"ST, Internet Stream Protocol",
        6:	"TCP, Transmission Control Protocol",
        7:	"UCL, CBT",	 
        8:	"EGP, Exterior Gateway Protocol",
        9:	"IGRP, Interior Gateway Routing Protocol",	 
        10:	"BBN RCC Monitoring",
        11:	"NVP, Network Voice Protocol",
        12:	"PUP",
        13:	"ARGUS",
        14:	"EMCON, Emission Control Protocol",	 
        15:	"XNET, Cross Net Debugger",
        16:	"Chaos",	 
        17:	"UDP, User Datagram Protocol",
        18:	"TMux, Transport Multiplexing Protocol",
        19:	"DCN Measurement Subsystems",
        20:	"HMP, Host Monitoring Protocol",
        21:	"Packet Radio Measurement",	 
        22:	"XEROX NS IDP",
        23:	"Trunk-1",	 
        24:	"Trunk-2",	 
        25:	"Leaf-1",	 
        26:	"Leaf-2",	 
        27:	"RDP, Reliable Data Protocol",
        28:	"IRTP, Internet Reliable Transaction Protocol",
        29:	"ISO Transport Protocol Class 4",
        30:	"NETBLT, Network Block Transfer",	 
        31:	"MFE Network Services Protocol", 
        32:	"MERIT Internodal Protocol",
        33:	"DCCP, Datagram Congestion Control Protocol",	 
        34:	"Third Party Connect Protocol",
        35:	"IDPR, Inter-Domain Policy Routing Protocol",
        36:	"XTP, Xpress Transfer Protocol",
        37:	"Datagram Delivery Protocol",
        38:	"IDPR, Control Message Transport Protocol",
        39:	"TP++ Transport Protocol",
        40:	"IL Transport Protocol", 
        41:	"IPv6 over IPv4",
        42:	"SDRP, Source Demand Routing Protocol",	 
        43:	"IPv6 Routing header",
        44:	"IPv6 Fragment header",	 
        45:	"IDRP, Inter-Domain Routing Protocol",	 
        46:	"RSVP, Reservation Protocol",
        47:	"GRE, General Routing Encapsulation",	 
        48:	"DSR, Dynamic Source Routing Protocol",	 
        49:	"BNA",
        50:	"ESP, Encapsulating Security Payload",	 
        51:	"AH, Authentication Header",
        52:	"I-NLSP, Integrated Net Layer Security TUBA", 
        53:	"SWIPE, IP with Encryption",
        54:	"NARP, NBMA Address Resolution Protocol",
        55:	"Minimal Encapsulation Protocol",
        56:	"TLSP, Transport Layer Security Protocol using Kryptonet key management",	 
        57:	"SKIP",
        58:	"ICMPv6, Internet Control Message Protocol for IPv6",
        59:	"IPv6 No Next Header",
        60:	"IPv6 Destination Options",	 
        61:	"Any host internal protocol",
        62:	"CFTP",
        63:	"Any local network", 
        64:	"SATNET and Backroom EXPAK",	 
        65:	"Kryptolan",	 
        66:	"MIT Remote Virtual Disk Protocol",	 
        67:	"Internet Pluribus Packet Core", 
        68:	"Any distributed file system",	 
        69:	"SATNET Monitoring",	 
        70:	"VISA Protocol", 
        71:	"Internet Packet Core Utility",	 
        72: "Computer Protocol Network Executive",	 
        73:	"Computer Protocol Heart Beat", 
        74:	"Wang Span Network",
        75:	"Packet Video Protocol",	 
        76:	"Backroom SATNET Monitoring",	 
        77:	"SUN ND PROTOCOL-Temporary",	 
        78:	"WIDEBAND Monitoring",
        79:	"WIDEBAND EXPAK",
        80:	"ISO-IP",
        81:	"VMTP, Versatile Message Transaction Protocol",	 
        82:	"SECURE-VMTP",
        83:	"VINES",
        84:	"TTP",	 
        85:	"NSFNET-IGP",	 
        86:	"Dissimilar Gateway Protocol",	 
        87:	"TCF",	 
        88:	"EIGRP",	 
        89:	"OSPF, Open Shortest Path First Routing Protocol",
        90:	"Sprite RPC Protocol",
        91:	"Locus Address Resolution Protocol",	 
        92:	"MTP, Multicast Transport Protocol",	 
        93:	"AX.25",
        94:	"IP-within-IP Encapsulation Protocol",	 
        95:	"Mobile Internetworking Control Protocol",	 
        96:	"Semaphore Communications Sec. Pro",
        97:	"EtherIP",
        98:	"Encapsulation Header",	 
        99: "Any private encryption scheme", 	 
        100: "GMTP",
        101: "IFMP, Ipsilon Flow Management Protocol",	 
        102: "PNNI over IP",
        103: "PIM, Protocol Independent Multicast", 
        104: "ARIS",
        105: "SCPS",	 
        106: "QNX",	 
        107: "Active Networks",	 
        108: "IPPCP, IP Payload Compression Protocol",
        109: "SNP, Sitara Networks Protocol",
        110: "Compaq Peer Protocol",
        111: "IPX in IP",
        112: "VRRP, Virtual Router Redundancy Protocol",
        113: "PGM, Pragmatic General Multicast",
        114: "any 0-hop protocol",
        115: "L2TP, Level 2 Tunneling Protocol",
        116: "DDX, D-II Data Exchange",
        117: "IATP, Interactive Agent Transfer Protocol", 
        118: "ST, Schedule Transfer",
        119: "SRP, SpectraLink Radio Protocol",
        120: "UTI",
        121: "SMP, Simple Message Protocol", 
        122: "SM",
        123: "PTP, Performance Transparency Protocol",
        124: "SIS over IPv4",
        125: "FIRE",
        126: "CRTP, Combat Radio Transport Protocol",
        127: "CRUDP, Combat Radio User Datagram",
        128: "SSCOPMCE",
        129: "IPLT", 
        130: "SPS, Secure Packet Shield",	 
        131: "PIPE, Private IP Encapsulation within IP",	 
        132: "SCTP, Stream Control Transmission Protocol",	 
        133: "Fibre Channel",
        134: "RSVP-E2E-IGNORE",
        135: "Mobility Header",
        136: "UDP-Lite, Lightweight User Datagram Protocol",
        137: "MPLS in IP",
        138: "MANET protocols",
        139: "HIP, Host Identity Protocol",
        140: "Shim6, Level 3 Multihoming Shim Protocol for IPv6",
        141: "WESP, Wrapped Encapsulating Security Payload",
        142: "ROHC, RObust Header Compression"
    }

    #Ip_Length = 20
    Ip_Header = Packet[14:34]
    Ip_Unpack = struct.unpack("!BBHHHBBH4s4s", Ip_Header)

    # Extraction
    Version_IHL = Ip_Unpack[0]
    Version = Version_IHL >> 4
    Internet_Header_Length = Version_IHL & 0xF
    IPHeader_Length = Internet_Header_Length * 4
    Total_Length = Ip_Unpack[2]
    Identification = Ip_Unpack[3]
    Fragment_Offset = Ip_Unpack[4] & 0x1FFF
    Time_To_Live = Ip_Unpack[5]
    Protocol_Number = Ip_Unpack[6]
    Checksum = Ip_Unpack[7]
    SourceIP = socket.inet_ntoa(Ip_Unpack[8])
    DestinationIP = socket.inet_ntoa(Ip_Unpack[9])

    if Protocol_Number in Protocols_Name:
        Protocol = Protocols_Name[Protocol_Number]
    else:
        Protocol = "Not define"

    
    print colored("[Intrnet Protocol-IP]", "yellow", attrs=["bold"])
    print colored("------------------", "yellow", attrs=["bold"])
    print colored("Version\t\t\t\t\t", "yellow", attrs=["bold"]), colored(":", "yellow", attrs=["bold"]), colored(Version, "white", attrs=["bold"])
    print colored("Internet Header Length\t\t\t", "yellow", attrs=["bold"]), colored(":", "yellow", attrs=["bold"]), colored(IPHeader_Length, "white", attrs=["bold"])
    print colored("Type Of Service\t\t\t\t", "yellow", attrs=["bold"]), colored(":", "yellow", attrs=["bold"]), colored(TypeOfService(Ip_Unpack[1]), "white", attrs=["bold"])
    print colored("Total Length\t\t\t\t", "yellow", attrs=["bold"]), colored(":", "yellow", attrs=["bold"]), colored(Total_Length, "white", attrs=["bold"])
    print colored("Identification\t\t\t\t", "yellow", attrs=["bold"]), colored(":", "yellow", attrs=["bold"]), colored(hex(Identification), "white", attrs=["bold"])
    print colored("Flags\t\t\t\t\t", "yellow", attrs=["bold"]), colored(":", "yellow", attrs=["bold"]), colored(IP_Flags(Ip_Unpack[4]), "white", attrs=["bold"])
    print colored("Fragment Offset\t\t\t\t", "yellow", attrs=["bold"]), colored(":", "yellow", attrs=["bold"]), colored(Fragment_Offset, "white", attrs=["bold"])
    print colored("TTL\t\t\t\t\t", "yellow", attrs=["bold"]), colored(":", "yellow", attrs=["bold"]), colored(Time_To_Live, "white", attrs=["bold"])
    print colored("Protocol\t\t\t\t", "yellow", attrs=["bold"]), colored(":", "yellow", attrs=["bold"]), colored(Protocol, "white", attrs=["bold"])
    print colored("Checksum\t\t\t\t", "yellow", attrs=["bold"]), colored(":", "yellow", attrs=["bold"]), colored(hex(Checksum), "white", attrs=["bold"])
    print colored("Source IP Address\t\t\t", "yellow", attrs=["bold"]), colored(":", "yellow", attrs=["bold"]), colored(SourceIP, "white", attrs=["bold"])
    print colored("Destination IP Address\t\t\t", "yellow", attrs=["bold"]), colored(":", "yellow", attrs=["bold"]), colored(DestinationIP, "white", attrs=["bold"])
    print "\n"

    
    # Checking Protocol field
    if Protocol_Number == 6:
        TCP(IPHeader_Length)
    if Protocol_Number == 17:
        UDP(IPHeader_Length)
    if Protocol_Number == 1:
        ICMP(IPHeader_Length)



# Decapsulate Type of service form ip packet
def TypeOfService(IP_PACKET):
	# Type of service have 5 Parameters : 1.Precedence - 2.Delay - 3.Throughput -  4.Reliability - 5.Monetary
	Precedence = {
				0: "[Routine]",
				1: "[Priority]",
				2: "[Immediate]",
				3: "[Flash]",
				4: "[Flash override]",
				5: "[CRITIC/ECP]",
				6: "[Internet Control]",
				7: "[Network Control]"
				}

	Delay = {
				0: "[Normal delay]",
				1: "[Low delay]"
			}

	Throughput = {
				0: "[Normal throughput]",
				1: "[High throughput]"
				}

	Reliability = {
				0: "[Normal reliability]",
				1: "[High reliabilit]"
				}

	Monetary = {
				0: "[Normal monetary cost]",
				1: "[Minimize monetary cost]"
				}

	# We need to shift all		
	# An indication of each --> 1	

	D = IP_PACKET & 0x10   # 00010000 / 16
	D >>= 4
	T = IP_PACKET & 0x8    # 00001000 / 8
	T >>= 3
	R = IP_PACKET & 0x4    # 00000100 / 4
	R >>= 2
	M = IP_PACKET & 0x2    # 00000010 / 2
	M >>= 1

	Dash = "-"
	TOS = Precedence[IP_PACKET >> 5] + Dash + Delay[D] + Dash + Throughput[T] + Dash + Reliability[R] + Dash + Monetary[M]
	return TOS



# Decapsulate Flags form ip packet
def IP_Flags(IP_PACKET):
    FlagR = {0: "[Reserved bit]"}
    FlagDF = {0: "[Fragment if necessary]", 1: "[Do not fragment]"}
    FlagMF = {0: "[This is the last fragment]", 1: "[More fragment follow this fragment]"}

    R = IP_PACKET & 0x8000
    R >>= 15
    DF = IP_PACKET & 0x4000
    DF >>= 14
    MF = IP_PACKET & 0x2000
    MF >>= 13

    Dash = "-"
    Flags = FlagR[R] + Dash + FlagDF[DF] + Dash + FlagMF[MF]
    return Flags



# Decapsulate Transmission Control Protocol segment
def TCP(IPHeaderLength):

    # 0                   1                   2                   3
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |          Source Port          |       Destination Port        |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                        Sequence Number                        |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                    Acknowledgment Number                      |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |  Data |           |U|A|P|R|S|F|                               |
    # | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
    # |       |           |G|K|H|T|N|N|                               |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |           Checksum            |         Urgent Pointer        |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                    Options                    |    Padding    |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                             data                              |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    # Source Port               : 16
    # Destination Port          : 16
    # Sequence Number           : 32
    # Acknowledgment Number     : 32
    # Data Offset               : 4
    # Reserved                  : 3
    # Flags                     : 6 (Each one is a one bit)
    # Window                    : 16
    # Checksum                  : 16
    # Urgent Pointer            : 16
    # Options                   : 0-40

    Tcp_Length = IPHeaderLength + 14
    Tcp_Header = Packet[Tcp_Length:Tcp_Length+20]
    Tcp_Unpack = struct.unpack("!HHLLBBHHH", Tcp_Header)

    # Extraction
    SourcePort =  Tcp_Unpack[0]
    DestinationPort = Tcp_Unpack[1]
    SequenceNumber = Tcp_Unpack[2]
    Acknowledgment = Tcp_Unpack[3] 
    DataOffset = Tcp_Unpack[4]
    TCPLength = DataOffset >> 4
    Flags = TCP_Flags(Tcp_Unpack[5])
    WindowSize = Tcp_Unpack[6]
    Checksum = Tcp_Unpack[7]


    print colored("[Transmission Control Protocol-TCP]", "magenta", attrs=["bold"])
    print colored("-----------------------------------", "magenta", attrs=["bold"])
    print colored("Source Port\t\t\t\t", "magenta", attrs=["bold"]), colored(":", "magenta", attrs=["bold"]), colored(SourcePort, "white", attrs=["bold"])
    print colored("Destination Port\t\t\t", "magenta", attrs=["bold"]), colored(":", "magenta", attrs=["bold"]), colored(DestinationPort, "white", attrs=["bold"])
    print colored("Sequence Number\t\t\t\t", "magenta", attrs=["bold"]), colored(":", "magenta", attrs=["bold"]), colored(SequenceNumber, "white", attrs=["bold"])
    print colored("Acknowledgment\t\t\t\t", "magenta", attrs=["bold"]), colored(":", "magenta", attrs=["bold"]), colored(Acknowledgment, "white", attrs=["bold"])
    print colored("Data Offset\t\t\t\t", "magenta", attrs=["bold"]), colored(":", "magenta", attrs=["bold"]), colored(DataOffset, "white", attrs=["bold"])
    print colored("TCP Length\t\t\t\t", "magenta", attrs=["bold"]), colored(":", "magenta", attrs=["bold"]), colored(TCPLength, "white", attrs=["bold"])
    print colored("Flags\t\t\t\t\t", "magenta", attrs=["bold"]), colored(":", "magenta", attrs=["bold"]), colored(Flags, "white", attrs=["bold"])
    print colored("Window size\t\t\t\t", "magenta", attrs=["bold"]), colored(":", "magenta", attrs=["bold"]), colored(WindowSize, "white", attrs=["bold"])
    print colored("Checksum\t\t\t\t", "magenta", attrs=["bold"]), colored(":", "magenta", attrs=["bold"]), colored(hex(Checksum), "white", attrs=["bold"])
    print "\n"


# Decapsulate Flags from TCP segment
def TCP_Flags(TCP_PACKET):
    Set_Flags = []

    Flag_URG = {0: "N", 1: "URG-Urgent"}
    Flag_ACK = {0: "N", 1: "ACK-Acknowledgment"}
    Flag_PSH = {0: "N", 1: "PSH-Push"}
    Flag_RST = {0: "N", 1: "RST-Reset"}
    Flag_SYN = {0: "N", 1: "SYN-Synchronize"}
    Flag_FIN = {0: "N", 1: "FIN-Finish"}

    URG = TCP_PACKET & 0x020
    URG >>= 5
    ACK = TCP_PACKET & 0x010
    ACK >>= 4
    PSH = TCP_PACKET & 0x008
    PSH >>= 3
    RST = TCP_PACKET & 0x004
    RST >>= 2
    SYN = TCP_PACKET & 0x002
    SYN >>= 1
    FIN = TCP_PACKET & 0x001
    FIN >>= 0

    if URG == 1:
        Set_Flags.append(Flag_URG[1])
    elif ACK == 1:
        Set_Flags.append(Flag_ACK[1])
    elif PSH == 1:
        Set_Flags.append(Flag_PSH[1])
    elif RST == 1:
        Set_Flags.append(Flag_RST[1])
    elif SYN == 1:
        Set_Flags.append(Flag_SYN[1])
    elif FIN == 1:
        Set_Flags.append(Flag_FIN[1])
    else:
        Set_Flags.append("[NO]")

    return Set_Flags



# Decapsulate User Datagram Protocol segment
def UDP(IPHeaderLength):

    # +--------------------------------------------------+
    # |       Source Port     |     Destination Port     |
    # +--------------------------------------------------+
    # |         Length        |         Checksum         |
    # +--------------------------------------------------+
    # |                      Data                        |
    # +--------------------------------------------------+

    # Source Port        : 16
    # Destination Port   : 16
    # Length             : 16
    # Checksum           : 16

    Udp_Length = IPHeaderLength + 14
    Udp_Header = Packet[Udp_Length:Udp_Length+8]
    Udp_unpack = struct.unpack("!HHHH", Udp_Header)

    # Extraction
    SourcePort = Udp_unpack[0]
    DestinationPort = Udp_unpack[1]
    UDPLength = Udp_unpack[2]
    Checksum = Udp_unpack[3]

    print colored("[User Datagram Protocol-UDP]", "blue", attrs=["bold"])
    print colored("----------------------------", "blue", attrs=["bold"])
    print colored("Source Port\t\t\t\t", "blue", attrs=["bold"]), colored(":", "blue", attrs=["bold"]), colored(SourcePort, "white", attrs=["bold"])
    print colored("Destination Port\t\t\t", "blue", attrs=["bold"]), colored(":", "blue", attrs=["bold"]), colored(DestinationPort, "white", attrs=["bold"])
    print colored("UDP Length\t\t\t\t", "blue", attrs=["bold"]), colored(":", "blue", attrs=["bold"]), colored(UDPLength, "white", attrs=["bold"])
    print colored("Checksum\t\t\t\t", "blue", attrs=["bold"]), colored(":", "blue", attrs=["bold"]), colored(hex(Checksum), "white", attrs=["bold"])
    print "\n"



# Decapsulate Internet Control Message Protocol packet
def ICMP(IPHeaderLength):

    # +------------------------------------------------+
    # |     Type     |     Code     |     Checksum     |
    # +------------------------------------------------+
    # |                      Data                      |
    # +------------------------------------------------+

    # Type       : 8
    # Code       : 8
    # Checksum   : 16

    Icmp_Length = IPHeaderLength + 14
    Icmp_Header = Packet[Icmp_Length:Icmp_Length+4]
    Icmp_Unpack = struct.unpack("!BBH", Icmp_Header)

    # Extraction
    ICMPType = Icmp_Unpack[0]
    if ICMPType == 8:
        Type = "Request"
    if ICMPType == 0:
        Type = "Reply"
    
    ICMPCode = Icmp_Unpack[1] 
    Checksum = Icmp_Unpack[2]

    print colored("[Internet Control Message Protocol-ICMP]", "grey", attrs=["bold"])
    print colored("----------------------------------------", "grey", attrs=["bold"])
    print colored("ICMP Type\t\t\t\t", "grey", attrs=["bold"]), colored(":", "grey", attrs=["bold"]), colored(Type, "white", attrs=["bold"])
    print colored("ICMP Code\t\t\t\t", "grey", attrs=["bold"]), colored(":", "grey", attrs=["bold"]), colored(ICMPCode, "white", attrs=["bold"])
    print colored("Checksum\t\t\t\t", "grey", attrs=["bold"]), colored(":", "grey", attrs=["bold"]), colored(hex(Checksum), "white", attrs=["bold"])
    print "\n"



def Main():
    Clear_terminal()
    Raw_socket()
    Packet_sniffer()

Main()
