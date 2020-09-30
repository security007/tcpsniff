import os
import socket
import struct
import ctypes

HOST = '192.168.1.11' #your ip to bind
while True:
	sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW,socket.IPPROTO_IP)
	sniffer.bind((HOST, 80))
	sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
	sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
	raw_buffer = sniffer.recvfrom(65565)[0]      
	ip_header = raw_buffer[0:20]        
	iph = struct.unpack('!BBHHHBBH4s4s' , ip_header)# Create our IP structure
	version_ihl = iph[0]        
	version = version_ihl >> 4        
	ihl = version_ihl & 0xF        
	iph_length = ihl * 4        
	ttl = iph[5]        
	protocol = iph[6]        
	s_addr = socket.inet_ntoa(iph[8]);        
	d_addr = socket.inet_ntoa(iph[9]);        
	tcp_header = raw_buffer[iph_length:iph_length+20]
	tcph = struct.unpack('!HHLLBBHHH' , tcp_header)
	
	source_port = tcph[0]
	dest_port = tcph[1]
	sequence = tcph[2]
	acknowledgement = tcph[3]
	doff_reserved = tcph[4]
	tcph_length = doff_reserved >> 4
	h_size = iph_length + tcph_length * 4
	data_size = len(raw_buffer) - h_size
	
	#get data from the packet
	data = raw_buffer[h_size:]
	try:
		domain = socket.gethostbyaddr(str(d_addr))[0]
	except:
		domain = "Can't Resolve Domain Name"
	print('IP -> Version:' + str(version) + ', Header Length:' + str(ihl) + ', TTL:' + str(ttl) + ', Protocol:' + str(protocol) + ', Source: '+ str(s_addr) + ', Destination: ' + str(d_addr)+'('+str(domain)+')')
	print('Data : ' + str(data.decode('ISO-8859-1','ignore')))
	print("")
	
	
	