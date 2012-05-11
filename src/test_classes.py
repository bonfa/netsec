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
import packet_printer

# test del parsing negli oggetti
filename = '../pacchetti-catturati/cattura2'

# creo l'oggetto che si interfaccia alla libpcap
packet_list = pcap.pcapObject()

# leggo da file i pacchetti sniffati
if packet_list.open_offline(filename) == 0:
	print 'error in opening file'
	sys.exit()
try:
	numero = 0
	while 1:
		# leggo il pacchetto
		packet = packet_list.next()
		if packet != None:				
			(pktlen, data, timestamp) = packet
			numero = numero + 1
			print '---[' + str(numero) + ']---'
			# creo il separatore di pacchetti
			separatore_pacchetti = Splitter(data)
			# separo il pacchetto
			ethernetPacket = separatore_pacchetti.get_packet_splitted()
			# stampo il pacchetto
			packet_printer.printEthernetHeader(ethernetPacket.header)
			packet_printer.printEapolHeader(ethernetPacket.payload.header)
			packet_printer.printEapolPayload(ethernetPacket.payload.payload)
		else:
			raise noPacketRead('packet_list.next()!= None','No packets found in input')	
		# creo il pacchetto che conterrà l'oggetto pacchetto
	print 'tutto ok'
except packetKindNotManaged:
	print 'pacchetto non gestito'
except noPacketRead:
	print 'pacchetti finiti'
except:
	print 'errori non previsti'
