#/usr/bin/python
# -*- coding: utf-8 -*-
'''
Calcolatore: little endian
'''

import pcap
import sys
from eapol_pack import EapolPacket,EapolHeader,EapolPayload,EapolKeyInformationField,EapolKeyDataField,KdeFormatKeyDataField,GtkFormatKeyDataField
from ether2_frame import EthernetIIFrame,EthernetIIHeader
from parser import Splitter
from exception import Error,packetKindNotManaged,noPacketRead

# test del parsing negli oggetti
filename = '../pacchetti-catturati/cattura2'

packet_list = pcap.pcapObject()
if packet_list.open_offline(filename) == 0:
	print 'error in opening file'
	sys.exit()
try:
	numero = 0
	while 1:
	# metodo preso dalla libreria plibpcap
		packet = packet_list.next()
		if packet!= None:				
			(pktlen, data, timestamp) = packet
			numero = numero + 1
			print '---[' + str(numero) + ']---'
			separatore_pacchetti = Splitter(data)
			#print '3'	
			#print '2'
			# creo il separatore di pacchetti
		else:
			raise noPacketRead('packet_list.next()!= None','No packets found in input')		
		# creo il pacchetto che conterrà l'oggetto pacchetto
		#separatore_pacchetti.ethernet_frame.to_string()
	print 'tutto ok'
except packetKindNotManaged:
	print 'pacchetto non gestito'
except noPacketRead:
	print 'pacchetti finiti'
#except:
#	print 'errori non previsti'
