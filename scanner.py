import socket
import os
import sys
from struct import *
from time import sleep
def checksum(msg):
    s = 0
     
    # loop taking 2 characters at a time
    for i in range(0, len(msg), 2):
        w = ord(msg[i]) + (ord(msg[i+1]) << 8 )
        s = s + w
     
    s = (s>>16) + (s & 0xffff);
    s = s + (s >> 16);
     
    #complement and mask to 4 byte short
    s = ~s & 0xffff
     
    return s


def _create(dest_ip,tcp_dest):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except socket.error , msg:
        print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
        sys.exit()
    
    # now start constructing the packet
    packet = '';
    source_ip = socket.gethostbyname("localhost")
    # ip header fields
    ip_ihl = 5  
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 0  # kernel will fill the correct total length
    ip_id = 54321   #Id of this packet
    ip_frag_off = 0
    ip_ttl = 255
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0    # kernel will fill the correct checksum
    ip_saddr = socket.inet_aton ( source_ip )   #Spoof the source ip address if you want to
    ip_daddr = socket.inet_aton ( dest_ip )
     
    ip_ihl_ver = (ip_ver << 4) + ip_ihl
    
    ip_header = pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
     
    # tcp header fields
    tcp_source = 10000   # source port
    tcp_seq = 454
    tcp_ack_seq = 0
    tcp_doff = 5    #4 bit field, size of tcp header, 5 * 4 (32 bits) = 20 bytes
    tcp_fin = 0
    tcp_syn = 1
    tcp_rst = 0
    tcp_psh = 0
    tcp_ack = 0
    tcp_urg = 0
    tcp_window = socket.htons (5840)    #   maximum allowed window size
    tcp_check = 0
    tcp_urg_ptr = 0
     
    tcp_offset_res = (tcp_doff << 4) + 0
    tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5)


    tcp_header = pack('!HHLLBBHHH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window, tcp_check, tcp_urg_ptr)
    
    
    source_address = socket.inet_aton(source_ip)
    dest_address = socket.inet_aton(dest_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header)
     
    psh = pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , tcp_length);
    psh = psh + tcp_header ;
     
    tcp_check = checksum(psh)
     
    # make the tcp header again and fill the correct checksum
    tcp_header = pack('!HHLLBBH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window) + pack('H' , tcp_check) + pack('!H' , tcp_urg_ptr)
     

    packet = ip_header + tcp_header
     
    #Send the packet finally
    s.sendto(packet, (dest_ip , 0 ))
    

def packet_sniffer(dest_ip):
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except socket.error , msg:
        print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
        sys.exit()

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

       	#print 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(src_add) + ' Destination Address : ' + str(dest_add)
    
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
        psh = tcp_flags & 0x10
        ack = tcp_flags & 0x08
        rst = tcp_flags & 0x04
        syn = tcp_flags & 0x02 
        fin = tcp_flags & 0x01
        
        #print 'Source Port : ' + str(src_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(seq_num) + ' Acknowledgement : ' + str(ack_seq_num) + ' TCP header length : ' + str(tcph_len)
        h_size = iph_length + tcph_len * 4
        data_size = len(packet) - h_size
         
        #get data from the packet
        data = packet[h_size:]
         
        #print 'Data : ' + data
        #print ' URG: ' + str(urg) +'\n PSH: ' +str(psh) + '\n ACK: ' +str(ack)+ '\n RST: ' +str(rst)+ '\n SYN: ' +str(syn)+ '\n FIN: ' +str(fin)	       
       
        if src_add == dest_ip:
            if syn == 2 and src_port !=10000:
                print "Open: " + str(src_port)


range_start = 1 
range_end = 1025
print "Destination ip or host name: "
dest_ip = raw_input()
print "-" * 60
print "Please wait, scanning remote host", dest_ip
print "-" * 60


def send_pack_to_port():
    for port in range(range_start,range_end):
	   _create(dest_ip,port)
    os.system("sudo killall -9 python")    #kill all  running processes
    pass

if os.fork() == 0:
    send_pack_to_port()
    while 1:
        pass
if os.fork() == 0:
    packet_sniffer(dest_ip)
    pass