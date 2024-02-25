import socket
import struct
import textwrap

TAB1 = '\t -'
TAB2 = '\t\t '
TAB3 = '\t\t\t '
TAB4 = '\t\t\t\t '

DATA_TAB1 = '\t '
DATA_TAB2 = '\t\t '
DATA_TAB3 = '\t\t\t '
DATA_TAB4 = '\t\t\t\t '


# Return properly formatted MAC address (bytes to hexadecimal)
def get_mac(bytes_mac):
    byte_str = map('{:02x}'.format, bytes_mac)
    mac_addr = ":".join(byte_str).upper()
    return mac_addr

# Unpacking IPv4 Packet:
def ipv4_Packet(data):
   # Unpack the first 20 bytes of the received data as IPv4 header
    ipv4_header = struct.unpack('!BBHHHBBH4s4s', data[:20])
    version = ipv4_header[0] >> 4  # Get the version from the first 4 bits
    header_length = (ipv4_header[0] & 15) * 4  # Get the header length in bytes
    ttl = ipv4_header[5]  # Time to live
    protocol = ipv4_header[6]  # Protocol (e.g., TCP, UDP)
    source_ip = socket.inet_ntoa(ipv4_header[8])  # Source IP address
    destination_ip = socket.inet_ntoa(ipv4_header[9])  # Destination IP address

    # Return the parsed IPv4 header fields
    return version, header_length, ttl, protocol, source_ip, destination_ip, data[20:]

# Unpack Ethernet frame which is in byte format
def eth_Frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac(dest_mac), get_mac(src_mac), socket.htons(proto), data[14:]


# Formats multi-line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])



def main():
    conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    conn.bind(('192.168.37.4', 0))     # Here you can change the IP by your actual IP, 127.0.0.1 is the loopback address or localhost.
    conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    while True:
        try:
            raw_data, addr = conn.recvfrom(65535)
            dest_mac, src_mac, eth_proto, data = eth_Frame(raw_data)
            print('\nEthernet frame: ')
            print("Source: {}, Destination: {}, Protocol: {}".format(src_mac, dest_mac, eth_proto))
            
            version, header_length, ttl, protocol, source_ip, destination_ip, data = ipv4_Packet(data)
            print(TAB1 + 'IPv4 Packet: ')
            print(TAB2 + 'Version: {}, Header: {}, TTL: {}'.format(version, header_length, ttl))
            print(TAB2 + 'Protocol: {}, Source: {}, Target: {}'.format(protocol, source_ip, destination_ip))
            print(TAB1 + 'Data: ')
            print(format_multi_line(DATA_TAB2, data))
        except Exception as e:
            print(e)
if __name__ == "__main__":
    main()
