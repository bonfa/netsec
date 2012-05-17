#/usr/bin/python
# -*- coding: utf-8 -*-
'''
Testo le funzioni di crittografia
'''

import pcap
import sys
from eapol_pack import EapolPacket,EapolHeader,EapolPayload,EapolKeyInformationField,EapolKeyDataField,KdeFormatKeyDataField,GtkFormatKeyDataField
from ether2_frame import EthernetIIFrame,EthernetIIHeader
from parser import Splitter
from exception import packetKindNotManaged,noPacketRead,pmkTooShortException
from four_way_crypto_utility import cryptographyManager
import packet_printer
from mic_utilities import TkipMicGenerator
#import base_crypto_utility

#definizione costanti
pwd = 'H6x&@!1uLQ*()!12c0x\\f^\'?|s<SNgh-'
path = '../pacchetti-catturati/'
mex = "Pairwise key expansion"
fourWayHandshakeMsg1Name = path + 'four_way_1'
fourWayHandshakeMsg2Name = path + 'four_way_2'
fourWayHandshakeMsg3Name = path + 'four_way_3'
fourWayHandshakeMsg4Name = path + 'four_way_4'
groupKeyHandshakeMsg1Name = path + 'group_key_1'
groupKeyHandshakeMsg2Name = path + 'group_key_2'



def getObjectPacket(filename):
	# creo l'oggetto che si interfaccia con libpcap
	packetHandler = pcap.pcapObject()

	# leggo il file
	if packetHandler.open_offline(filename) == 0:
		raise packetReaderException('packetHandler.open_offline(filename) = 0','Error in reading file')	
	else:
		packet = packetHandler.next()
		if packet != None:
			# Splitto il file
			(pktlen, data, timestamp) = packet
			# Creo l'oggetto che splitta il file
			packetSplitter = Splitter(data)			
			# Ritorno l'oggetto
			return packetSplitter.get_packet_splitted()
		else:
			raise noPacketRead('packet_list.next()!= None','No packets found in input')	


def printPacket(ethernetPacket):
	packet_printer.printEthernetHeader(ethernetPacket.header)
	packet_printer.printEapolHeader(ethernetPacket.payload.header)
	packet_printer.printEapolPayload(ethernetPacket.payload.payload)




##main
#print pwd
fourWayHandshakeMsg_1 = getObjectPacket(fourWayHandshakeMsg1Name)
fourWayHandshakeMsg_2 = getObjectPacket(fourWayHandshakeMsg2Name)
fourWayHandshakeMsg_3 = getObjectPacket(fourWayHandshakeMsg3Name)
fourWayHandshakeMsg_4 = getObjectPacket(fourWayHandshakeMsg4Name)
groupKeyHandshakeMsg_1 = getObjectPacket(groupKeyHandshakeMsg1Name)
groupKeyHandshakeMsg_2 = getObjectPacket(groupKeyHandshakeMsg2Name)


#printPacket(fourWayHandshakeMsg_1)
#printPacket(fourWayHandshakeMsg_2)
#printPacket(fourWayHandshakeMsg_3)
#printPacket(fourWayHandshakeMsg_4)
##controllare che tutti i pacchetti siano eapol, che tutti i campi incrociati corrispondano (src e dst) ecc


try:
	length = 512
	ANonce = fourWayHandshakeMsg_2.payload.payload.key_nonce
	SNonce = fourWayHandshakeMsg_1.payload.payload.key_nonce
	AA = fourWayHandshakeMsg_1.header.source_address
	SPA = fourWayHandshakeMsg_1.header.destination_address
	manager = cryptographyManager(pwd,mex,AA,SPA,ANonce,SNonce,length)
	[kek,kck,tk,micKey1,micKey2] = manager.getKeys()
	#stampo quelle che dovrebbero essere le chiavi di sessione
	print packet_printer.stringInHex(kek) + '   L = ' + str(len(kek)*8) + '  bit'
	print packet_printer.stringInHex(kck) + '   L = ' + str(len(kck)*8) + '  bit'
	print packet_printer.stringInHex(tk) + '   L = ' + str(len(tk)*8) + '  bit'
	print packet_printer.stringInHex(micKey1) + '   L = ' + str(len(micKey1)*8) + '  bit'
	print packet_printer.stringInHex(micKey2) + '   L = ' + str(len(micKey2)*8) + '  bit'

	#prendo il secondo pacchetto, provo a calcolarne il MIC e vedo se è uguale
	packetHandler = pcap.pcapObject()
	packetHandler.open_offline(fourWayHandshakeMsg2Name)	
	packet = packetHandler.next()
	(pktlen, data, timestamp) = packet
		
	# creo l'oggetto che si occupa di generare il MIC
	micGenerator = TkipMicGenerator(data,micKey2)	
	# genero il MIC	
	mic = micGenerator.getMic()
	# stampo il MIC
	print  'MIC = ' + packet_printer.stringInHex(mic)


except pmkTooShortException:
	print 'La pmk è troppo corta L = ' + str(len(pwd))
	


