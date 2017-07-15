from pcapfile import savefile
from pcapfile.protocols.linklayer import ethernet
from pcapfile.protocols.network import ip
from pcapfile.protocols.transport import tcp
from pcapfile.protocols.transport import udp
import binascii
import csv
import sys
import time
import ctypes
import traceback
import os

line_count = 0; total_lines = 0
MaxId = 0; cant_packet = 0; arrivalTime = 0; elapsed = 0

dirname_traces = './Traces'
dirname_results = './Results'
MAC_address_ISP = '00:21:a0:56:28:17'

file_intranet = open(dirname_results + '/intranet.csv','a')
file_extranet = open(dirname_results + '/extranet.csv','a')
file_intranet.write('#    0   |   1    |     2     |   3   |   4   |  5  |   6  |  7   |    8   |   9    | 10 ' + '\n')
file_intranet.write('#arr_time,size_pkt,sizePayload,MAC_src,MAC_dst,proto,IP_src,IP_dst,port_src,port_dst,flags' + '\n')
file_extranet.write('#    0   |   1    |     2     |   3   |   4   |  5  |   6  |  7   |    8   |   9    | 10 ' + '\n')
file_extranet.write('#arr_time,size_pkt,sizePayload,MAC_src,MAC_dst,proto,IP_src,IP_dst,port_src,port_dst,flags' + '\n')

Flows = {}
Nodes = {}
sub_redes = {
'172.141.0.0/19' : [0, 0, 0], 
'172.141.32.0/19' : [0, 0, 0], 
'172.141.64.0/19' : [0, 0, 0], 
'172.141.96.0/19' : [0, 0, 0], 
'172.141.128.0/19' : [0, 0, 0], 
'172.141.160.0/19' : [0, 0, 0], 
'172.141.192.0/19' : [0, 0, 0], 
'172.141.224.0/19' : [0, 0, 0],
'70.191.0.0/19' : [0, 0, 0], 
'70.191.32.0/19' : [0, 0, 0], 
'70.191.64.0/19' : [0, 0, 0], 
'70.191.96.0/19' : [0, 0, 0], 
'70.191.128.0/19' : [0, 0, 0], 
'70.191.160.0/19' : [0, 0, 0], 
'70.191.192.0/19' : [0, 0, 0], 
'70.191.224.0/19' : [0, 0, 0]
}

def ip2bin(ip):
	octets = map(int, ip.split('/')[0].split('.')) # '1.2.3.4'=>[1, 2, 3, 4]
	binary = '{0:08b}{1:08b}{2:08b}{3:08b}'.format(*octets)
	range = int(ip.split('/')[1]) if '/' in ip else None
	return binary[:range] if range else binary
	
def ipIsMatch(ip,subnet):
	mask = int(subnet.split('/')[1])
	a1 = ip2bin(ip)[:mask]
	a2 = ip2bin(subnet)
	if int(a1,2) == int(a2,2):
		ismatch = True
	else:
		ismatch = False
	return ismatch

for dir_trace in sorted(os.listdir(dirname_traces)):
	print "File primer nivel: " , dir_trace
	#Se analiza cada sub-traza que esta en el directorio */Traces
	for file_trace in sorted(os.listdir(str(dirname_traces+'//'+dir_trace))):
		
		start1=time.clock()
		print "File segundo nivel: " , file_trace
		
		input_file = open(dirname_traces + '//' + dir_trace + '//' + file_trace, 'rb')
		#Se crea el header
		header = savefile._load_savefile_header(input_file)
		
		if savefile.__validate_header__(header):
			#Se empieza a leer paquete por paquete del archivo input_file
			while True:
				#Leemos un paquete
				pkt =savefile. _read_a_packet(input_file, ctypes.pointer(header), 0)
				cant_packet += 1
				line_count += 1
				
				if line_count == 100000:
					total_lines += line_count
					print " %d Lineas Procesadas" %total_lines
					line_count = 0		

				if pkt:
					try:
						eth_frame = ethernet.Ethernet(pkt.raw())
						#Se procede a extraer los datos de la capa2 
						capa2 = str(eth_frame).split(";")
						mac_src = capa2[0]
						mac_dst = capa2[1]
						#Analisis si el paquete tiene el campo Vlan
						frame = eth_frame.payload
						validador_vlan= frame[4:8]
						validador_ip = frame[8:10]
						#Si el paquete cumple las condiciones, contiene el header vlan
						if validador_vlan == "0800" and validador_ip == "45":
							eth_frame.payload = frame[8:]		
						ip_packet = ip.IP(binascii.unhexlify(eth_frame.payload))
						#se procede a extraeir los datos de la capa 3
						capa3 = str(ip_packet).split(";")
						ip_src = capa3[0]
						ip_dst = capa3[1]
						protocolo = capa3[2]
						ip_hl = capa3[3]
						size_pkt = pkt.packet_len
						#Capturamos los arrivalTimes de cada paquete
						time_present = float(pkt.timestamp_us)*0.000001+float(pkt.timestamp)
						
						if cant_packet == 1: 
							time_old = time_present
						deltaTime = time_present - time_old
						time_old = time_present
						arrivalTime += deltaTime
						
						#se procede a extraer los datos de la capa 4, se coloca 40 pues es a partir
						#de este valor que comienza el payload de la capa de transporte
						
						#creamos los bits de los flags SYN y FIN
						bit_SYN='0';bit_FIN='0'
						#si el protocolo es TCP
						if (int(protocolo) == 6):
							try:
								tcp_packet = tcp.TCP(binascii.unhexlify(eth_frame.payload[40:]))
								#Extraemos los datos de la capa 4
								capa4_tcp = str(tcp_packet).split(";")
								port_src = capa4_tcp[0]
								port_dst = capa4_tcp[1]
								
								seqnum_tcp = capa4_tcp[2]
								acknum_tcp = capa4_tcp[3]
								data_offset_tcp = capa4_tcp[4]
								bit_urg = capa4_tcp[5]
								bit_ack = capa4_tcp[6]
								bit_psh = capa4_tcp[7]
								bit_rst = capa4_tcp[8]
								bit_syn = capa4_tcp[9]
								bit_fin = capa4_tcp[10]
								win_tcp = capa4_tcp[11]
								flags_tcp = capa4_tcp[12]
							except:
								port_src = '0'
								port_dst = '0'
						#si el protocolo es UDP
						elif (int(protocolo) == 17):
							try:
								udp_packet = udp.UDP(binascii.unhexlify(eth_frame.payload[40:]))
								#Extraemos los datos de la capa 4
								capa4_udp = str(udp_packet).split(";")
								port_src = capa4_udp[0]
								port_dst = capa4_udp[1]	
							except:
								port_src = '0'
								port_dst = '0'
						#para otros protocolos
						else:
							port_src = '0'; port_dst = '0'
						
						#Analisis de las sesiones
						#key session rule: intranet IP comes first
						#extranet
						if str(mac_src) == MAC_address_ISP:
							session_key = ip_dst+'&'+ip_src+'&'+protocolo+'&'+port_dst+'&'+port_src
						#intranet
						elif str(mac_dst) == MAC_address_ISP:
							session_key = ip_src+'&'+ip_dst+'&'+protocolo+'&'+port_src+'&'+port_dst
						
						#Analisis de los nodos solo en la intranet
						#if (Nodes.has_key(str(session_key.split("&")[0])) == False):
						if (Nodes.has_key(str(ip_src)) == False):
							#Numero de sesiones por Nodo
							values_Node = [0]
							curDict_Node = {str(ip_src): values_Node}
							Nodes.update(curDict_Node)
						
						#Si el paquete pertenece a un nuevo Flow 
						if (Flows.has_key(str(session_key)) == False):
							#Buscamos a que sub red pertenece la sesiones
							#ip_src = session_key.split("&")[0]
							for sub_red in sub_redes.keys():
								if ipIsMatch(ip_src,sub_red):
									sub_red = sub_red
									break
							#Los valores son [pktCount, sizeFlow, SubRed]
							values = [ 0, 0, str(sub_red)]
							curDict = {str(session_key): values}
							Flows.update(curDict)
							
							#Actualizamos el numero de sesiones en cada SubRed
							sub_redes[str(sub_red)][2] += 1
							
							#Actualizamos el numero de sesiones por Nodo solo de la Intranet
							#if str(mac_dst) == MAC_address_ISP:
							Nodes[str(ip_src)][0] += 1
							
						old_value_flow = Flows[str(session_key)]
						#Actualizamos los valores del Flow
						old_value_flow[0] += 1
						old_value_flow[1] += size_pkt
						
						#Actualizamos los valores de las Sub-Redes
						old_sub_red = sub_redes[str(old_value_flow[2])]
						old_sub_red[0] += 1
						old_sub_red[1] += size_pkt
						
						if (int(protocolo) == 6):
							pkt_payload = size_pkt - (14 + 4*int(ip_hl) + int(data_offset_tcp))
						else:
							pkt_payload = size_pkt - (14 + 4*int(ip_hl) + 8)
						
						#extranet
						if str(mac_src) == MAC_address_ISP:
							#TCP
							if (int(protocolo) == 6):
								file_extranet.write( str(deltaTime) + ',' + str(size_pkt) + ',' + str(pkt_payload) + ',' + str(mac_src) + ',' + str(mac_dst)  + ',' + str(protocolo) + ',' + str(ip_src) + ',' + str(ip_dst) + ',' + str(port_src) + ',' + str(port_dst) + ',' + str(flags_tcp) + '\n')
							#UDP
							elif (int(protocolo) == 17):
								file_extranet.write( str(deltaTime) + ',' + str(size_pkt) + ',' + str(pkt_payload) + ',' + str(mac_src) + ',' + str(mac_dst)  + ',' + str(protocolo) + ',' + str(ip_src) + ',' + str(ip_dst) + ',' + str(port_src) + ',' + str(port_dst) + '\n')
							#ICMP
							elif (int(protocolo) == 1):
								file_extranet.write( str(deltaTime) + ',' + str(size_pkt) + ',' + str(pkt_payload) + ',' + str(mac_src) + ',' + str(mac_dst)  + ',' + str(protocolo) + ',' + str(ip_src) + ',' + str(ip_dst) + '\n')
							
						#intranet
						elif str(mac_dst) == MAC_address_ISP:
							#TCP
							if (int(protocolo) == 6):
								file_intranet.write( str(deltaTime) + ',' + str(size_pkt) + ',' + str(pkt_payload) + ',' + str(mac_src) + ',' + str(mac_dst)  + ',' + str(protocolo) + ',' + str(ip_src) + ',' + str(ip_dst) + ',' + str(port_src) + ',' + str(port_dst) + ',' + str(flags_tcp) + '\n')
							#UDP
							elif (int(protocolo) == 17):
								file_intranet.write( str(deltaTime) + ',' + str(size_pkt) + ',' + str(pkt_payload) + ',' + str(mac_src) + ',' + str(mac_dst)  + ',' + str(protocolo) + ',' + str(ip_src) + ',' + str(ip_dst) + ',' + str(port_src) + ',' + str(port_dst) + '\n')
							#ICMP
							elif (int(protocolo) == 1):
								file_intranet.write( str(deltaTime) + ',' + str(size_pkt) + ',' + str(pkt_payload) + ',' + str(mac_src) + ',' + str(mac_dst)  + ',' + str(protocolo) + ',' + str(ip_src) + ',' + str(ip_dst) + '\n')
					
					except AssertionError:
						#No se analiza el paquete porque no es IPv4
						i=1
						#print "exception-No se analiza el paquete"
				else:
					break
		
print cant_packet , " paquetes analizados"		
#Se guarda en los diccionarios
save_flow_dict = csv.writer(open('./Dicts/flow_dict.csv', 'w'))
save_flow_dict.writerow(['#key_session|pktCount|sizeFlow(Bytes)|SubRed'])
start2 = time.clock()
for val in Flows.items():
	save_flow_dict.writerow([val[0], val[1][0], val[1][1], val[1][2]])
elapsed2 = time.clock() - start2
print "tiempo que se guarda el dict - Flow: %s" %(elapsed2)

save_subnet_dict = csv.writer(open('./Dicts/subnet_dict.csv', 'w'))
save_subnet_dict.writerow(['#sub_red_prefix|pktCount|size(Bytes)|sessionCount'])
start3 = time.clock()
for val in sub_redes.items():
	save_subnet_dict.writerow([val[0], val[1][0], val[1][1], val[1][2]])
elapsed3 = time.clock() - start3
print "tiempo que se guarda el dict - SubNet: %s" %(elapsed3)

save_nodes_dict = csv.writer(open('./Dicts/nodes_dict.csv', 'w'))
save_nodes_dict.writerow(['#ip_Node|sessionCountByNode'])
start4 = time.clock()
for val in Nodes.items():
	save_nodes_dict.writerow([val[0], val[1][0]])
elapsed4 = time.clock() - start4
print "tiempo que se guarda el dict - Node: %s" %(elapsed4)	
		

	
	
