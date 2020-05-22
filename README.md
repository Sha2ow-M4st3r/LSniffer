# PSniffer

![Screenshot](http://s9.picofile.com/file/8348064526/it_sssup_rtn_sniffer154.png)

LSniffer is a C script that allows you to sniffing all incoming and outgoing packets from the network. It can capture and decrypt packets for **Ethernet, ARP, IP, TCP, UDP, and ICMP** protocols.




## What is packet sniffer

A packet analyzer (also known as a packet sniffer) is a computer program or piece of computer hardware that can intercept and log traffic that passes over a digital network or part of a network.

Packet capture is the process of intercepting and logging traffic. As data streams flow across the network, the sniffer captures each packet and, if needed, decodes the packet's raw data, showing the values of various fields in the packet, and analyzes its content according to the appropriate RFC or other specifications.

![Screenshot](http://s9.picofile.com/file/8348063150/network_sniffing.png)

For more information: [Wikipedia](https://en.wikipedia.org/wiki/Packet_analyzer)

## Protocols

- [Ethernet](https://en.wikipedia.org/wiki/Ethernet)
- [Address Resolution Protocol-ARP](https://en.wikipedia.org/wiki/Address_Resolution_Protocol)
- [Internet Protocol-IP](https://en.wikipedia.org/wiki/Internet_Protocol)
- [Transmission Control Protocol-TCP](https://en.wikipedia.org/wiki/Transmission_Control_Protocol)
- [User Datagram Protocol-UDP](https://en.wikipedia.org/wiki/User_Datagram_Protocol)
- [Internet Control Message Protocol-ICMP](https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol)


## Screenshots

![Screenshot](http://s13.picofile.com/file/8397900668/Screenshot_at_2020_05_22_11_57_38.png)


## Installation

```markdown
**LSniff only work on linux platform**

- sudo git clone https://github.com/Sha2ow-M4st3r/LSniffer.git
- cd LSniffer
- sudo gcc LSniffer.c -o LSniffer.out
```

## Usage

```markdown

sudo ./LSniffer.out
```

**Never forget: You Can't Run From Your Shadow. But You Can Invite It To Dance**
