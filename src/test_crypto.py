#/usr/bin/python
# -*- coding: utf-8 -*-
'''
Testo le funzioni di crittografia
'''
import sys
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src/common_utility')
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src/crypto')
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src/packetStruct')
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src')

import pcap
import sys
from eapol_pack import EapolPacket,EapolHeader,EapolPayload,EapolKeyInformationField,EapolKeyDataField,KdeFormatKeyDataField,GtkFormatKeyDataField
from ether2_frame import EthernetIIFrame,EthernetIIHeader
from parser import Splitter
from exception import packetKindNotManaged,noPacketRead,pmkTooShortException
from four_way_crypto_utility import keyGenerator,cryptoManager
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
	'''
	ottiene l'oggetto pacchetto a partire dal nome del pacchetto
	'''
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
	'''
	stampa il pacchetto
	'''
	packet_printer.printEthernetHeader(ethernetPacket.header)
	packet_printer.printEapolHeader(ethernetPacket.payload.header)
	packet_printer.printEapolPayload(ethernetPacket.payload.payload)


def printEapolPacket(eapolPacket):
	'''
	stampa il pacchetto eapol
	'''
	printEapolHeader(eapolPacket[0:4])
	printEapolPayload(eapolPacket[4:])


def printEapolHeader(eapolHeader):
	print 'EAPOL HEADER'
	print '   PROTOCOL VERSION = ' + eapolHeader[0:1].encode("hex")
	print '   PACKET TYPE = ' + eapolHeader[1:2].encode("hex")
	print '   PACKET BODY LENGTH = ' + eapolHeader[2:4].encode("hex")
		

def printEapolPayload(eapolPayload):
	print 'EAPOL PAYLOAD'
	print '   DESCRYPTOR TYPE = ' + eapolPayload[0:1].encode("hex")
	print '   KEY INFO = ' + eapolPayload[1:3].encode("hex")
	print '   KEY LENGTH = ' + eapolPayload[3:5].encode("hex")
	print '   KEY REPLAY COUNTER = ' + eapolPayload[5:13].encode("hex")
	print '   KEY NONCE = ' + eapolPayload[13:45].encode("hex")
	print '   EAPOL KEY IV = ' + eapolPayload[45:61].encode("hex")
	print '   KEY RSC = ' + eapolPayload[61:69].encode("hex")
	print '   RESERVED = ' + eapolPayload[69:77].encode("hex")
	print '   KEY MIC = ' + eapolPayload[77:93].encode("hex")
	print '   KEY DATA LENGTH = ' + eapolPayload[93:95].encode("hex")
	print '   KEY DATA = ' +eapolPayload[95:].encode("hex")



'''main'''
fourWayHandshakeMsg_1 = getObjectPacket(fourWayHandshakeMsg1Name)
fourWayHandshakeMsg_2 = getObjectPacket(fourWayHandshakeMsg2Name)
fourWayHandshakeMsg_3 = getObjectPacket(fourWayHandshakeMsg3Name)
fourWayHandshakeMsg_4 = getObjectPacket(fourWayHandshakeMsg4Name)

try:
	# definisco i parametri di input
	ANonce = fourWayHandshakeMsg_1.payload.payload.key_nonce
	SNonce = fourWayHandshakeMsg_2.payload.payload.key_nonce
	AA = fourWayHandshakeMsg_1.header.source_address
	SPA = fourWayHandshakeMsg_1.header.destination_address
	
	# stampo questi parametri
	print 'AA = ' + packet_printer.macAddressToString(AA)
	print 'SPA = ' + packet_printer.macAddressToString(SPA)
	print 'ANonce = ' +packet_printer.stringInHex(ANonce)
	print 'SNonce = ' +packet_printer.stringInHex(SNonce)

	# creo le chiavi
	keyGen = keyGenerator(pwd,mex,AA,SPA,ANonce,SNonce)
	[kck,kek,tk,authenticatorMicKey,supplicantMicKey] = keyGen.getKeys()
	


	# prendo il secondo pacchetto, provo a calcolarne il MIC e vedo se è uguale
	packetHandler = pcap.pcapObject()
	packetHandler.open_offline(fourWayHandshakeMsg2Name)	
	packet = packetHandler.next()
	(pktlen, data, timestamp) = packet
	
	# creo l'oggetto dal campo data	e stampo il pacchetto
	packetSplitter = Splitter(data)			
	dataObj = packetSplitter.get_packet_splitted()
	printPacket(dataObj)	
	
	# creo il pacchetto con 
	micGenerator = cryptoManager(data,dataObj,kek,kck)
	dataWithNullField = micGenerator.clearKeyMicField()
	eapolDataWithNullField = micGenerator.getEapolPayload(dataWithNullField)
	
	# stampo solo l'eapol payload
	printEapolPacket(eapolDataWithNullField)
	
	#stampo il pacchetto con il campo mic annullato
	packetSplitter = Splitter(dataWithNullField)			
	obj2 = packetSplitter.get_packet_splitted()
	# genero il MIC	
	mic = micGenerator.getMic()
	# stampo il MIC
	print  'MIC = ' + mic



except pmkTooShortException:
	print 'La pmk è troppo corta L = ' + str(len(pwd))
	


