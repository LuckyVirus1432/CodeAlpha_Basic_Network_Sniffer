'''
|*| Code Alpha Internship Task 1

| Note | => This file is only for Linux OS and requires the sudo/root permission to sniff packets over the internet

* Network Packet Sniffing Tool in Python
    As we know the data flows in the form of packets through an interface/medium.
    This packet is known as Ethernet Frame which we are about to sniff from network.

* Ethernet Frame structure:
        sync    receiver    sender      type    payload(ip/arp frame + padding)     crc
       8byte    6byte       6byte       2byte           46-1500byte                 4byte
    
    In the above frame sync & crc are not important for humans but receiver sender type & payload has some juicy information which will be used by human.
    receiver => the device MAC which is going to receive the packet sent by the sender
    sender => the device MAC which is sending data to the receiver.
    type => Type of the protocol used in the frame (IPv4, IPv6 or ARP)
    payload => this is actual data the sender is sending to the receiver
    
    
'''

import socket
import struct   # Allows us to package binary data in a structured way
import textwrap

TAB1 = '\t -'
TAB2 = '\t\t '
TAB3 = '\t\t\t '
TAB4 = '\t\t\t\t '

DATA_TAB1 = '\t '
DATA_TAB2 = '\t\t '
DATA_TAB3 = '\t\t\t '
DATA_TAB4 = '\t\t\t\t '


# Return properly formatted mac address (bytes to hexadecimal)
def get_mac(bytes_mac):
    byte_str = map('{:02x}'.format, bytes_mac)
    mac_addr = ":".join(byte_str).upper()
    return mac_addr
    # here {:02x} is the formatting specifier used to represent an integer as a two-digit hexadecimal number.
    
#Unpack Ethernet frame which is in byte format:
def eth_Frame(data):
    #To get src dest mac address and proto, we've to unpack first 14 bytes of the frame only.
    # struct.unpack('format_in_bytes', binary_data)
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    # here ! => network data (not useful)
    #     6s => 6 byte char/string data
    #     H  => Short unsigned integer data
    #   data[:14] => to read only first 14 bytes of the frame
    return get_mac(dest_mac), get_mac(src_mac), socket.htons(proto), data[14:]





'''
    Now, we're Unpacking the IP Packet.
    Each IP Packet contains IP header, where all juicy information lies. such as Source IP & Destination IP.
    Every computer has It's own IP address, used to communicate over the intenet.

'''
# Formatting the IPv4 adrress properly ( bytes to Decimal)
def get_Ip(ipv4):
    ip = '.'.join(map(str, ipv4))
    return ip

# Unpacking IPv4 Packet:
def ipv4_Packet(data):
    version_header_len = data[0]
    version = version_header_len >> 4  # Bit shifted 4 to the right (first 4 bytes)
    header_len = (version_header_len & 15) * 4
    ttl, proto, src, target = struct.unpack("! 8x B B 2x 4s 4s", data[:20])
    return version, header_len, ttl, proto, get_Ip(src), get_Ip(target), data[header_len:]


# Unpacks ICMP packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# Unpacks TCP packet/segment
def tcp_packet(data):
    src_port, dest_port, seq, ack, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 5
    flag_psh = (offset_reserved_flags & 8) >> 5
    flag_rst = (offset_reserved_flags & 4) >> 5
    flag_syn = (offset_reserved_flags & 2) >> 5
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, seq, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

def udp_packet(data):
    src_port, dest_port, length = struct.unpack('! H H 2x', data[:8])
    return src_port, dest_port, length, data[8:]


# Formats multi-line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])



# Main function
def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while(True):
        raw_data, addr = conn.recvfrom(65535)
        dest_mac, src_mac, eth_proto, data = eth_Frame(raw_data)
        print('\nEthernet frame: ')
        print(TAB1 + "Source: {}, Destination: {}, Protocol: {}".format(src_mac, dest_mac, eth_proto))

        # 8 for IPv4
        if eth_proto == 8:
            (version, header_len, ttl, proto, src, target, data) = ipv4_Packet(data)
            print(TAB1 + 'IPv4 Packet: ')
            print(TAB2 + 'Version: {}, Header: {}, TTL: {}'.format(version, header_len, ttl))
            print(TAB2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))
            
            # checking IPv4 packet protocol
            # 1 ICMP, 2 IGMP, 6 TCP, 17 UDP
            # ICMP
            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print(TAB1 + 'ICMP Packet: ')
                print(TAB2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
                print(TAB2 + 'Data: ')
                print(format_multi_line(DATA_TAB3, data))
            # TCP
            elif proto == 6:
                src_port, dest_port, seq, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_packet(data)
                print(TAB1 + 'TCP Packet: ')
                print(TAB2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                print(TAB2 + 'Sequence: {}, Acknowledgment: {}'.format(seq, ack))
                print(TAB2 + 'Flags: ')
                print(TAB3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                print(TAB2 + 'Data: ')
                print(format_multi_line(DATA_TAB3, data))
            # UDP
            elif proto == 17:
                src_port, dest_port, length = udp_packet(data)
                print(TAB1 + 'UDP Packet: ')
                print(TAB2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, length))
                print(TAB2 + 'Data: ')
                print(format_multi_line(DATA_TAB3, data))
            # Other
            else:
                print(TAB1 + 'Data: ')
                print(format_multi_line(DATA_TAB2, data))
        else:
            print('Data: ')
            print(format_multi_line(DATA_TAB1, data))


if __name__ == '__main__':
    main()