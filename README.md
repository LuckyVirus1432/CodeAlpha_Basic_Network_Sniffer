# CodeAlpha_Basic_Network_Sniffer
Python networking tool (Network Packet Sniffer)

# Code Alpha Internship Task 1

[ Note ] => There are two files and both requires the sudo/root or Administrative permission to sniff packets over the internet.
[*] Network Packet Sniffing Tool in Python :-
  [1] First We are Unpacking the Ethernet Frame:
    - As we know the data flows in the form of packets through an interface/medium.
    - This packet is known as Ethernet Frame which we are about to sniff from network.
    - Ethernet Frame contains MAC address of the Devices


	* Ethernet Frame structure:
        sync    receiver    sender      type    payload(ip/arp frame + padding)     crc
       8byte    6byte       6byte       2byte           46-1500byte                 4byte
    

- In the above frame sync & crc are not important for humans but receiver sender type & payload has some juicy information which will be used by human.
      receiver => the device MAC which is going to receive the packet sent by the sender
      sender => the device MAC which is sending data to the receiver.
      type => Type of the protocol used in the frame (IPv4, IPv6 or ARP)
      payload => this is actual data the sender is sending to the receiver
  [2] Unpacking IPv4 Packet:
    - In every Ethernet frame, there is an IPv4 Packet.
    - Each IPv4 Packet contains IP header.
    - Now We are going to unpack the IPv4 header.
  [3] Unpacking the IPv4 Packet protocol:
    - There are some common protocols used in IPv4 packet.
    - Such as ICMP, TCP, UDP with there port numbers as 1, 6 & 17 respectively.

  After unpacking Data Packet upto the above [3] steps...Print every thing on the console.
  Such as,
   
    	Etherent Frame:
      - Source: xx:xx:xx:xx:xx:xx Destination: xx:xx:xx:xx:xx:xx, Protocol: x
      - IPv4 Packet:
          Version: 4, Header: 20, TTL: xx
          Protocol: xx, Source: xxx.xxx.xx.xx, Target: xxx.xxx.xxx.xxx
      - TCP Packet:
          Source Port: xxxxx, Destination Port: 443
          Sequence: xxxxxxxxxx, Acknowledgment: xxxxxxxxx
          Flags: 
              URG: x, ACK: x, PSH: x, RST: x, SYN: x, FIN: x
          Data:
              \x16\x03\x03\x00\x7a\x02\x00\x00\x76\x03\x03\x1c\x44\x7a\x65\x4c\x1a\x5b\x84
                         \x65\xd3\x66\x17\x26\x3e\xd6\xa5\x6c\x5f\x8b\xd3\x7d\xdc\xf9\xb6\x93\x84\xb0
                         \x79\xaa\xd8\x37\xea\x20\x09\x14\x9f\x1a\xf2\x3b\xf4\x0c\x83\x4a\xf3\x92\xf4
                         \xba\xe4\xd6\x87\x90\xda\x36\x67\x00\x9a\x4e\xd2\xc2\xad\x56\x13\x37\x0e\xbe
                         \x13\x01\x00\x00\x2e\x00\x33\x00\x24\x00\x1d\x00\x20\x9d\x87\x7a\xb9\xfd\xa7






# Codealpha Internship Task2:

Snort NIDS: (Version 3)
1. If you are using VMs then please make sure that both VMS are in a same network, So that they can communicate with each other.
2. Install snort:
	
 		apt install snort -y (on kali linux = snort v3)
3. Configure the snort main configuration file:
  
 		cat /etc/snort/snort.lua (change HOME_NET or EXTERNAL_NET according to you or leave it as it is.
4. Write the local rules or use default rules:

		cat  /etc/snort/rules/local.rules
5. Start snort tool and perform the attack:
	(check the alerts)
	

For testing purpose try to protect Metasploitable linux server (vulnerable by default) and use metasploit-framework to exploit the Metasploitable machine from linux.
Host (EXTERNAL_NET): Kali Linux or any OS trying to breach Metasploitable
Target (HOME_NET)  : Metasploitable 

* Here are some possible network attacks we are going to detect:
  
		alert icmp any any -> HOME_NET any (msg: "ICMP packet found...Seems to be pinged by someone"; sid:100001; rev:1;)
		alert tcp any any -> HOME_NET 21 (msg: "SSH Login Attempt .. !"; sid:100002; rev1;)
		alert tcp any any -> HOME_NET 22 (msg: "FTP Authentication Attempt..!"; sid:100003; rev:3;)
	(Refer this official documentation for writing rules: https://docs.snort.org/ )

General format of the rule is as followed:
	action protocol source_ip source_port direction_symbol dest_ip dest_port (msg: ""; [other options];)

I've used hping3 tool to send arbitary TCP/IP packets to the Network
