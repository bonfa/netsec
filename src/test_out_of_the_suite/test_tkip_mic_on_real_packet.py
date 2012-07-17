#/usr/bin/python
# -*- coding: utf-8 -*-
'''

'''
import sys
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src/utilities')
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src/common_utility')
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src/crypto')
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src/packetStruct')


import pcap
import sys
from eapol_pack import EapolPacket,EapolHeader,EapolPayload,EapolKeyInformationField,EapolKeyDataField,KdeFormatKeyDataField,GtkFormatKeyDataField
from ether2_frame import EthernetIIFrame,EthernetIIHeader
from packet_parser import Splitter
from exception import packetKindNotManaged,noPacketRead,pmkTooShortException
from four_way_crypto_utility import keyGenerator,cryptoManager,passphraseToPSKMap
import packet_printer



'''Costanti'''
passphrase = 'H6x&@!1uLQ*()!12c0x\\f^\'?|s<SNgh-'
ssid = 'WWWLAN'
#psk = "3f4eb9a38ba03f3a28235fd038971be12845a57169c2801d729afa6711f6db96".decode("hex")	
path = '../../pacchetti-catturati/'
messaggioPerLaGenerazioneDiChiavi = "Pairwise key expansion"
NomeDelPacchetto1DelFourWayHandshake = path + 'four_way_1'
NomeDelPacchetto2DelFourWayHandshake = path + 'four_way_2'
NomeDelPacchetto3DelFourWayHandshake = path + 'four_way_3'
NomeDelPacchetto4DelFourWayHandshake = path + 'four_way_4'



'''Funzioni'''
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
			return data,packetSplitter.get_packet_splitted()
		else:
			raise noPacketRead('packet_list.next()!= None','No packets found in input')	




'''main'''
pacchetto1DelFourWayHandshake,oggetto1Del4WayHandshake = getObjectPacket(NomeDelPacchetto1DelFourWayHandshake)
pacchetto2DelFourWayHandshake,oggetto2Del4WayHandshake = getObjectPacket(NomeDelPacchetto2DelFourWayHandshake)

# estraggo i nonces
ANonce = oggetto1Del4WayHandshake.payload.payload.key_nonce
SNonce = oggetto2Del4WayHandshake.payload.payload.key_nonce
AA = oggetto1Del4WayHandshake.header.source_address
SPA = oggetto1Del4WayHandshake.header.destination_address

print 'AA=' + AA
print 'SPA=' + SPA
print 'ANonce=' + ANonce
print 'SNonce=' + SNonce

# genero la psk a partire dalla passphrase
pskGen = passphraseToPSKMap(passphrase,ssid)
psk = pskGen.getPsk()

# genero le chiavi
keyGen = keyGenerator(psk,messaggioPerLaGenerazioneDiChiavi,AA,SPA,ANonce,SNonce)
[kck,kek,tk,authenticatorMicKey,supplicantMicKey] = keyGen.getKeys()

# prendo il secondo pacchetto e ne calcolo il MIC
# annullo il mic
micGen = cryptoManager(pacchetto2DelFourWayHandshake,oggetto2Del4WayHandshake,kek,kck)
# ottengo il mic
mic = micGen.getMic()

#stampo il pacchetto
packet_printer.printEthernetHeader(oggetto2Del4WayHandshake.header)
packet_printer.printEapolHeader(oggetto2Del4WayHandshake.payload.header)
packet_printer.printEapolPayload(oggetto2Del4WayHandshake.payload.payload)

#stampo il mic
#print "KCK = " + kck
#print "KEK = " + kek
print 'MIC_2 = ' + mic


##provo a calcolarlo anche per i pacchetti 3 e 4
pacchetto3DelFourWayHandshake,oggetto3Del4WayHandshake = getObjectPacket(NomeDelPacchetto3DelFourWayHandshake)
pacchetto4DelFourWayHandshake,oggetto4Del4WayHandshake = getObjectPacket(NomeDelPacchetto4DelFourWayHandshake)

# prendo il secondo pacchetto e ne calcolo il MIC
# annullo il mic
micGen3 = cryptoManager(pacchetto3DelFourWayHandshake,oggetto3Del4WayHandshake,kek,kck)
# ottengo il mic
mic3 = micGen3.getMic()
#stampo il mic
print 'MIC_3 = ' + mic3


# prendo il secondo pacchetto e ne calcolo il MIC
# annullo il mic
micGen4 = cryptoManager(pacchetto4DelFourWayHandshake,oggetto4Del4WayHandshake,kek,kck)
# ottengo il mic
mic4 = micGen4.getMic()
#stampo il mic
print 'MIC_4 = ' + mic4


