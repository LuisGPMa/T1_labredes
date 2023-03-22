import binascii
import socket
import struct
import sys
import pandas as pd

HTTP_PORT = 80
HTTPS_PORT = 443
DNS_PORT = 53
DHCP_PORTS = [67, 68]
UDP = 17
TCP = 6
ICMP = 1
ICMPV6 = 58
IPV4 = '0800'
IPV6 = '86dd'
ARP = '0806'
ARP_OPCODES = {'0001':'Request', '0002':'Reply'}
ICMP_TYPES = {0:'Reply', 8:'Request'}
ICMPV6_TYPES = {128:'Request', 129:'Reply'}
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

packets_df = pd.DataFrame(columns=['Enlace', 'Rede', 'Transporte', 'Aplicacao', 'Tamanho', 'Porta', 'Request_ou_Reply'])

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
    return int(len(binascii.hexlify(packet).decode('utf-8')) / 2)

while True:
    eth = s.recvfrom(65565)
    packet_size = size_in_bytes(eth[0])
    parsed_eth = ethernet_header(eth[0])
    dest_mac, src_mac, ethertype, eth_data = [binascii.hexlify(item).decode('utf-8') for item in parsed_eth]
    #print (f"Destination MAC: {dest_mac}", f"Source MAC: {src_mac}", f"Type: {ethertype}", f"Size in bytes: {packet_size}")
    enlace = 'Ethernet'
    if ethertype == IPV4:        
        rede = 'IPv4'
        ipheader = eth[0][14:34]
        transporte = int(binascii.hexlify(ipheader[9:10]).decode('utf-8'), base=16)
        protocolo_transporte = ''
        ip_header = struct.unpack("!12s4s4s", ipheader)
        aplicacao = ''
        dest_port = ''
        ICMP_req_or_rply = ''
        # print ("Source IP:", socket.inet_ntoa(ip_header[1]), " Destination IP:", socket.inet_ntoa(ip_header[2]), f'Transport: {transporte}')
        if transporte == ICMP:
            protocolo_transporte = 'ICMP'
            icmp_header = eth[0][34:38]
            icmp_type = int(binascii.hexlify(icmp_header[:1]).decode('utf-8'), base=16)
            if icmp_type in ICMP_TYPES.keys():
                ICMP_req_or_rply = ICMP_TYPES[icmp_type]
            else:
                ICMP_req_or_rply = 'Other'

            
        elif transporte == UDP:
            protocolo_transporte = 'UDP'
            udp_header = eth[0][34:42]
            src_port = int(binascii.hexlify(udp_header[:2]).decode('utf-8'), base=16)
            dest_port = int(binascii.hexlify(udp_header[2:4]).decode('utf-8'), base=16)
            if src_port == DNS_PORT or dest_port == DNS_PORT:
                aplicacao = 'DNS'
            elif src_port in DHCP_PORTS or dest_port in DHCP_PORTS:
                aplicacao = 'DHCP'
            
        elif transporte == TCP:
            protocolo_transporte = 'TCP'
            tcp_ports = eth[0][34:38]
            src_port = int(binascii.hexlify(tcp_ports[:2]).decode('utf-8'), base=16)
            dest_port = int(binascii.hexlify(tcp_ports[2:4]).decode('utf-8'), base=16)
            if src_port == HTTP_PORT or dest_port == HTTP_PORT:
                aplicacao = 'HTTP'
            elif src_port == HTTPS_PORT or dest_port == HTTPS_PORT:
                aplicacao = 'HTTPS'
        packets_df.loc[packets_df.shape[0]] = [enlace, rede, protocolo_transporte, aplicacao, packet_size, dest_port, ICMP_req_or_rply]
        
    elif ethertype == IPV6:
        rede = 'IPV6'
        hexified = binascii.hexlify(eth[0]).decode('utf-8')
        ipv6_header = hexified[28:108]
        transporte = int(ipv6_header[12:14], base=16)
        aplicacao = ''
        print(transporte)
        #print(binascii.hexlify(eth[0]).decode('utf-8'))
        if transporte == ICMPV6:
            protocolo_transporte = 'ICMPV6'
            icmp6_type = int(hexified[108:110],base=16)
            #print(icmp6_type)#funfando
            # icmp_type = binascii.hexlify(icmp_header[:1]).decode('utf-8')
            # ICMP_req_or_rply = ICMP_TYPES[icmp_type]
        elif transporte == UDP:
            protocolo_transporte = 'UDP'
            udp_ports = hexified[108:116]
            src_port = int(udp_ports[:4], base=16)
            dest_port = int(udp_ports[4:], base=16)
            print(src_port, dest_port)
            if src_port == DNS_PORT or dest_port == DNS_PORT:
                aplicacao = 'DNS'
            elif src_port in DHCP_PORTS or dest_port in DHCP_PORTS:
                aplicacao = 'DHCP'
        elif transporte == TCP:
            protocolo_transporte = 'TCP'
            tcp_ports = hexified[108:116]
            src_port = int(tcp_ports[:4], base=16)
            dest_port = int(tcp_ports[4:], base=16) #funfando
            print(src_port, dest_port)
            if src_port == HTTP_PORT or dest_port == HTTP_PORT:
                aplicacao = 'HTTP'
            elif src_port == HTTPS_PORT or dest_port == HTTPS_PORT:
                aplicacao = 'HTTPS'
    if ethertype == ARP:
        ARP_header = arp_header(eth[0])
        packets_df.loc[packets_df.shape[0]] = ['ARP', '', '', '', packet_size, '', ARP_OPCODES[ARP_header[4]]]
