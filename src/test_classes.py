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
from exception import Error,packetKindNotManaged

# test del parsing negli oggetti
filename = '../pacchetti-catturati/cattura2'

packet_list = pcap.pcapObject()
if packet_list.open_offline(filename) == 0:
	print 'error in opening file'
	sys.exit()
try:
	while 1:
	# metodo preso dalla libreria plibpcap
		(pktlen, data, timestamp) = packet_list.next()
		print '2'
		# creo il separatore di pacchetti
		separatore_pacchetti = Splitter(data)
		print '3'	
		# creo il pacchetto che conterrà l'oggetto pacchetto
		separatore_pacchetti.ethernet_frame.to_string()
	print 'tutto ok'
except packetKindNotManaged:
	print 'pacchetto non gestito'
except:
	print 'errori non previsti'
