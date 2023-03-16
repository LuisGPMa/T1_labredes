import binascii
import socket
import struct
import sys
import pandas as pd



IPV4 = '0800'
IPV6 = '86dd'
ARP = '0806'
ARP_OPCODES = {'0001':'Request', '0002':'Reply'}
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

packets_df = pd.DataFrame(columns=['Enlace', 'Rede', 'Transporte', 'Aplicacao', 'Tamanho'])
print(packets_df.head())

def ethernet_header(raw_data):
    #IPV4 TYPE: 0800
    #IPV6 TYPE: 86DD
    #ARP TYPE: 0806
    dest, src, ethertype = struct.unpack("!6s6s2s", raw_data[:14])
    data = raw_data[14:]
    return dest, src, ethertype, data

def arp_header(packet):

    (a ,b ,c ,d ,e ,f ,g ,h ,i ) = struct.unpack('2s2s1s1s2s6s4s6s4s',packet[14:42])

    hw_type=(binascii.hexlify(a)).decode('utf-8')
    proto_type=(binascii.hexlify(b)).decode('utf-8')
    hw_size=(binascii.hexlify(c)).decode('utf-8')
    proto_size=(binascii.hexlify(d)).decode('utf-8')
    opcode=(binascii.hexlify(e)).decode('utf-8')

    return (hw_type,proto_type,hw_size,proto_size,opcode,socket.inet_ntoa(g),socket.inet_ntoa(i))

def size_in_bytes(packet):
    return int(len(binascii.hexlify(packet[14:]).decode('utf-8')) / 2)

while True:
    eth = s.recvfrom(65565)
    packet_size = size_in_bytes(eth[0])
    parsed_eth = ethernet_header(eth[0])
    dest_mac, src_mac, ethertype, eth_data = [binascii.hexlify(item).decode('utf-8') for item in parsed_eth]
    print (f"Destination MAC: {dest_mac}", f"Source MAC: {src_mac}", f"Type: {ethertype}", f"Size in bytes: {packet_size}")
    if ethertype == IPV4:
        ipheader = eth[0][14:34]
        ip_header = struct.unpack("!12s4s4s", ipheader)
        print ("Source IP:", socket.inet_ntoa(ip_header[1]), " Destination IP:", socket.inet_ntoa(ip_header[2]))
    if ethertype == ARP:
        print(arp_header(eth[0])[4])
        packets_df.loc[packets_df.shape[0]] = ['ARP', '', '', '', packet_size]
        