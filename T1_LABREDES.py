import binascii
import socket
import struct
import pandas as pd

PRINT_EVERY_N_PACKETS = 10
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
ARP_OPCODES = {1:'Request', 2:'Reply'}
ICMP_TYPES = {0:'Reply', 8:'Request'}
ICMPV6_TYPES = {128:'Request', 129:'Reply'}
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

packets_df = pd.DataFrame(columns=['Enlace', 'Rede', 'Transporte', 'Aplicacao', 'Tamanho', 'Porta', 'Request_ou_Reply'])

def display_curr_stats():
    min, avg, max = min_avg_max()
    ARP_req_amnt, ARP_rply_amnt, ARP_req_perc, ARP_rply_perc = get_ARP_statistics()
    IPV4_amnt, IPV4_perc = get_protocol_amnt_and_perc('Rede', 'IPv4')
    ICMP_amnt, ICMP_perc = get_protocol_amnt_and_perc('Transporte', 'ICMP')
    ICMP_req_amnt, ICMP_rply_amnt, ICMP_req_perc, ICMP_rply_perc = get_ICMP_statistics()
    IPV6_amnt, IPV6_perc = get_protocol_amnt_and_perc('Rede', 'IPv6')
    ICMPV6_amnt, ICMPV6_perc = get_protocol_amnt_and_perc('Transporte', 'ICMPv6')
    ICMPV6_req_amnt, ICMPV6_rply_amnt, ICMPV6_req_perc, ICMPV6_rply_perc = get_ICMP_statistics('ICMPv6')
    UDP_amnt, UDP_perc = get_protocol_amnt_and_perc('Transporte', 'UDP')
    TCP_amnt, TCP_perc = get_protocol_amnt_and_perc('Transporte', 'TCP')
    portas_TCP_mais_acessadas = get_portas_mais_acessadas('TCP')
    portas_UDP_mais_acessadas = get_portas_mais_acessadas('UDP')
    HTTP_amnt, HTTP_perc = get_protocol_amnt_and_perc('Aplicacao', 'HTTP')
    DNS_amnt, DNS_perc = get_protocol_amnt_and_perc('Aplicacao', 'DNS')
    DHCP_amnt, DHCP_perc = get_protocol_amnt_and_perc('Aplicacao', 'DHCP')
    HTTPS_amnt, HTTPS_perc = get_protocol_amnt_and_perc('Aplicacao', 'HTTPS')
    print('___________________________________________________________________')
    print(f'Tamanho minimo: {min}, Tamanho maximo: {max}, Tamanho medio: {avg}')
    print('Dados do protocolo ARP:')
    format_and_print_reqs_and_replies('ARP', ARP_req_amnt, ARP_rply_amnt, ARP_req_perc, ARP_rply_perc)
    format_and_print_protocol_stats_as_df('IPv4', IPV4_amnt, IPV4_perc)
    format_and_print_protocol_stats_as_df('ICMP', ICMP_amnt, ICMP_perc)
    format_and_print_reqs_and_replies('ICMP', ICMP_req_amnt, ICMP_rply_amnt, ICMP_req_perc, ICMP_rply_perc)
    format_and_print_protocol_stats_as_df('IPv6', IPV6_amnt, IPV6_perc)
    format_and_print_protocol_stats_as_df('ICMPv6', ICMPV6_amnt, ICMPV6_perc)
    format_and_print_reqs_and_replies('ICMPv6', ICMPV6_req_amnt, ICMPV6_rply_amnt, ICMPV6_req_perc, ICMPV6_rply_perc)
    format_and_print_protocol_stats_as_df('UDP', UDP_amnt, UDP_perc)
    print(f'    Portas UDP mais acessadas: {portas_UDP_mais_acessadas}')
    format_and_print_protocol_stats_as_df('TCP', TCP_amnt, TCP_perc)
    print(f'    Portas TCP mais acessadas: {portas_TCP_mais_acessadas}')
    format_and_print_protocol_stats_as_df('HTTP', HTTP_amnt, HTTP_perc)
    format_and_print_protocol_stats_as_df('HTTPS', HTTPS_amnt, HTTPS_perc)
    format_and_print_protocol_stats_as_df('DNS', DNS_amnt, DNS_perc)
    format_and_print_protocol_stats_as_df('DHCP', DHCP_amnt, DHCP_perc)
    print(f'Total de pacotes capturados: {packets_df.shape[0]}')
    
    
    
    
def format_and_print_protocol_stats(protocol, amnt, perc):
    print(f'Dados do protocolo {protocol}:')
    print(f'    Qtd de pacotes {protocol}: {amnt}, Perc. de pacotes {protocol}: {perc}')
    
def format_and_print_protocol_stats_as_df(protocol, amnt, perc):
    newdf = pd.DataFrame([[amnt, str(perc)+'%']], columns=['qtd', 'perc'], index=[protocol])
    print(newdf)

def format_and_print_reqs_and_replies(protocol, req_amnt, rply_amnt, req_perc, rply_perc):
    print(f'    Qtd de reqs {protocol}: {req_amnt}, Qtd de rplies {protocol}: {rply_amnt}, Perc. de reqs {protocol}: {req_perc}, Perc. de rplies {protocol}: {rply_perc}')
    
        
def get_ARP_statistics():
    ARP_packets = packets_df[packets_df['Enlace'] == 'ARP']
    ARP_req_packets = ARP_packets[ARP_packets['Request_ou_Reply']=='Request']
    ARP_rply_packets = ARP_packets[ARP_packets['Request_ou_Reply']=='Reply']
    ARP_req_amnt = ARP_req_packets.shape[0]
    ARP_rply_amnt = ARP_rply_packets.shape[0]
    try:
        ARP_req_packets_perc = ARP_req_amnt/ARP_packets.shape[0]
    except:
        ARP_req_packets_perc = 0
    try:
        ARP_rply_packets_perc = ARP_rply_amnt/ARP_packets.shape[0]
    except:
        ARP_rply_packets_perc = 0
    
    return (ARP_req_amnt, ARP_rply_amnt, ARP_req_packets_perc, ARP_rply_packets_perc)

def get_ICMP_statistics(ICMP_ver='ICMP'):
    ICMP_packets = packets_df[packets_df['Transporte'] == ICMP_ver]
    ICMP_req_packets = ICMP_packets[ICMP_packets['Request_ou_Reply']=='Request']
    ICMP_rply_packets = ICMP_packets[ICMP_packets['Request_ou_Reply']=='Reply']
    ICMP_req_amnt = ICMP_req_packets.shape[0]
    ICMP_rply_amnt = ICMP_rply_packets.shape[0]
    try:
        ICMP_req_packets_perc = ICMP_req_amnt/ICMP_packets.shape[0]
    except:
        ICMP_req_packets_perc = 0
    try:
        ICMP_rply_packets_perc = ICMP_rply_amnt/ICMP_packets.shape[0]
    except:
        ICMP_rply_packets_perc = 0
    
    return (ICMP_req_amnt, ICMP_rply_amnt, ICMP_req_packets_perc, ICMP_rply_packets_perc)

def get_portas_mais_acessadas(TCP_ou_UDP='TCP'):
    packets = packets_df[packets_df['Transporte'] == TCP_ou_UDP]
    sorted_by_sort_frequency = packets.groupby(['Porta'])['Transporte'].count().reset_index(name='Count').sort_values(['Count'], ascending=False)
    return list(sorted_by_sort_frequency['Porta'])[:5]
    
def min_avg_max():
    min_size = packets_df['Tamanho'].min()
    avg_size = '{:.4}'.format(packets_df['Tamanho'].mean())
    max_size = packets_df['Tamanho'].max()
    
    return (min_size, avg_size, max_size)

#usage example: get_protocol_perc('Rede', 'IPv4')
def get_protocol_amnt_and_perc(level, protocol):    
    packets = packets_df[packets_df[level] == protocol]
    amnt = packets.shape[0]
    try:
        packets_perc = amnt/packets_df.shape[0]
    except:
        packets_perc = 0
    
    return (amnt, '{:.2%}'.format(packets_perc))

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
        rede = 'IPv6'
        hexified = binascii.hexlify(eth[0]).decode('utf-8')
        ipv6_header = hexified[28:108]
        transporte = int(ipv6_header[12:14], base=16)
        aplicacao = ''
        protocolo_transporte = ''
        dest_port = ''
        ICMPV6_req_or_rply = ''
        if transporte == ICMPV6:
            protocolo_transporte = 'ICMPv6'
            icmp6_type = int(hexified[108:110],base=16)
            #print('_________________________', icmp6_type)
            if icmp6_type in ICMPV6_TYPES.keys():
                ICMPV6_req_or_rply = ICMPV6_TYPES[icmp6_type]
            else:
                ICMPV6_req_or_rply = 'Other'
        elif transporte == UDP:
            protocolo_transporte = 'UDP'
            udp_ports = hexified[108:116]
            src_port = int(udp_ports[:4], base=16)
            dest_port = int(udp_ports[4:], base=16)
            if src_port == DNS_PORT or dest_port == DNS_PORT:
                aplicacao = 'DNS'
            elif src_port in DHCP_PORTS or dest_port in DHCP_PORTS:
                aplicacao = 'DHCP'
        elif transporte == TCP:
            protocolo_transporte = 'TCP'
            tcp_ports = hexified[108:116]
            src_port = int(tcp_ports[:4], base=16)
            dest_port = int(tcp_ports[4:], base=16)
            if src_port == HTTP_PORT or dest_port == HTTP_PORT:
                aplicacao = 'HTTP'
            elif src_port == HTTPS_PORT or dest_port == HTTPS_PORT:
                aplicacao = 'HTTPS'
        packets_df.loc[packets_df.shape[0]] = [enlace, rede, protocolo_transporte, aplicacao, packet_size, dest_port, ICMPV6_req_or_rply]
        
    if ethertype == ARP:
        #print('ARPARPARP')
        ARP_header = arp_header(eth[0])
        rede = 'ARP'
        opcode = int(binascii.hexlify(eth[0][21:22]).decode('utf-8'), base=16)
        print('-------------------------------------', opcode)

        packets_df.loc[packets_df.shape[0]] = [rede, '', '', '', packet_size, '', ARP_OPCODES[opcode]]

    if packets_df.shape[0]%PRINT_EVERY_N_PACKETS==0:
        display_curr_stats()
