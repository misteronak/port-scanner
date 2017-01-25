import socket
import os
import sys
from struct import *
from time import sleep
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
except socket.error , msg:
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()

print "enter ip for which you want to sniff packets: "
sniff_ip = raw_input()
print "sniffing packets from: ", sniff_ip
while True:
    data = s.recvfrom(65565)
                
    #packet string from tuple
    packet = data[0]
     
    #take first 20 characters for the ip header
    ip_header = packet[0:20]
     
    #now unpack them :)
    iph = unpack('!BBHHHBBH4s4s' , ip_header)
     
    version_ihl = iph[0]
    
    version = version_ihl >> 4
    ihl = version_ihl &0xF

    iph_length = ihl * 4


    ttl = iph[5]
    protocol = iph[6]
    src_add = socket.inet_ntoa(iph[8])
    dest_add = socket.inet_ntoa(iph[9])

    

    tcp_header = packet[iph_length:iph_length+20]
    tcph = unpack('!HHLLBBHHH', tcp_header)
    src_port = tcph[0]
    dest_port = tcph[1]
    seq_num = tcph[2]
    ack_seq_num = tcph[3]
    doff_res = tcph[4]
    tcph_len = doff_res >> 4

    #flag values
    tcp_flags = tcph[5]
    urg = tcp_flags & 0x20
    ack = tcp_flags & 0x10
    psh = tcp_flags & 0x08
    rst = tcp_flags & 0x04
    syn = tcp_flags & 0x02 
    fin = tcp_flags & 0x01
    
    
    h_size = iph_length + tcph_len * 4
    data_size = len(packet) - h_size
     
    #get data from the packet_sniffer
    data = packet[h_size:]
    if src_add == sniff_ip:
        print 'Source Port : ' + str(src_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(seq_num) + ' Acknowledgement : ' + str(ack_seq_num) + ' TCP header length : ' + str(tcph_len)
        print 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(src_add) + ' Destination Address : ' + str(dest_add) 
        print 'Data : ' + data
        print ' URG: ' + str(urg) +'\n PSH: ' +str(psh) + '\n ACK: ' +str(ack)+ '\n RST: ' +str(rst)+ '\n SYN: ' +str(syn)+ '\n FIN: ' +str(fin)	       
   