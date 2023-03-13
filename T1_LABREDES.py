import binascii
import socket
import struct
import sys
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

def get_mac_addr(addr):
    pass

def ethernet_head(raw_data):
    #IPV4 TYPE: 0800
    #IPV6 TYPE: 86DD
    #ARP TYPE: 0806
    dest, src, type = struct.unpack("!6s6s2s", raw_data[:14])
    data = raw_data[14:]
    return dest, src, type, data

#IPV4 TYPE: 0800
#IPV6 TYPE: 86DD
#ARP TYPE: 0806

while True:
    eth = s.recvfrom(65565)
    parsed_eth = ethernet_head(eth[0])
    source_mac = 
    print ("Destination MAC:", binascii.hexlify(parsed_eth[0]), " Source MAC:", binascii.hexlify(parsed_eth[1]) ," Type:",binascii.hexlify(parsed_eth[2]))
    if 
    ipheader = eth[0][14:34]
    ip_header = struct.unpack("!12s4s4s", ipheader)
    print ("Source IP:", socket.inet_ntoa(ip_header[1]), " Destination IP:", socket.inet_ntoa(ip_header[2]))
