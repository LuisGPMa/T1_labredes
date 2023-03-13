import binascii
import socket
import struct
import sys
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

def get_mac_addr(addr):
    pass

def ethernet_head(raw_data):
 dest, src, prototype = struct.unpack("!6s6s2s", raw_data[:14])
 #dest_mac = get_mac_addr(dest)
 #src_mac = get_mac_addr(src)
 #proto = socket.htons(prototype)
 data = raw_data[14:]
 return dest, src, prototype,data

#IPV4 TYPE: 0800
#IPV6 TYPE: 86DD
#ARP TYPE: 0806

while True:
    eth = s.recvfrom(65565)
    parsed_eth = ethernet_head(eth[0])
    print ("Destination MAC:", binascii.hexlify(parsed_eth[0]), " Source MAC:", binascii.hexlify(parsed_eth[1]) ," Type:",binascii.hexlify(parsed_eth[2]))
