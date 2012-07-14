#/usr/bin/python
# -*- coding: utf-8 -*-

'''

'''

import sys
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src/utilities')
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src/common_utility')
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src/crypto')
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src/packetStruct')
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src')

# Set log level to benefit from Scapy warnings
import logging
logging.getLogger("scapy").setLevel(1)

from scapy.all import *
import pcap
from wpa_struct_for_scapy import *
from packet_printer import stringInHex
from packet_subfields import getEapolKeyPart
from consistence_checker import FourWayHandshakeConsistenceChecker
from four_way_crypto_utility import passphraseToPSKMap,keyGenerator,cryptoManager
from exception import PacketError
from packet_parser import Splitter


def print4WayHandshakeWarning(mex):
	if mex != '':
		print 'WARNING: abnormalities in the input packets:'
		print mex
		print 'The program will try to continue the execution'



#definisco le variabili principali
path = '../pacchetti-catturati/'
mex = "Pairwise key expansion"
fourWayHandshakeMsg1Name = path + 'four_way_1'
fourWayHandshakeMsg2Name = path + 'four_way_2'
fourWayHandshakeMsg3Name = path + 'four_way_3'
fourWayHandshakeMsg4Name = path + 'four_way_4'
groupKeyHandshakeMsg1Name = path + 'group_key_1'
groupKeyHandshakeMsg2Name = path + 'group_key_2'
pms = 'H6x&@!1uLQ*()!12c0x\\f^\'?|s<SNgh-'
ssid = 'WWWLAN'

#leggo i quattro pacchetti

# rdpcap torna una lista e quindi devo prendere il primo elemento
p1 = rdpcap(fourWayHandshakeMsg1Name)[0] 
p2 = rdpcap(fourWayHandshakeMsg2Name)[0]
p3 = rdpcap(fourWayHandshakeMsg3Name)[0]
p4 = rdpcap(fourWayHandshakeMsg4Name)[0]

#definisco il controllore di pacchetti
controlloreErrori = FourWayHandshakeConsistenceChecker(p1,p2,p3,p4)

try: 
	#controlla la coerenza sui mac_addres
	controlloreErrori.macAddressConsistence()
	#ritorno le anormalità nei pacchetti
	abnormalities = controlloreErrori.getAbnormalities()
	#stampa le abnormalità nei pacchetti se ci sono
	print4WayHandshakeWarning(abnormalities)
	
	#genero psk a partire dal pms (pre master secret) e dall'SSID
	pskGenerator = passphraseToPSKMap(pms,ssid)
	psk = pskGenerator.getPsk()

	#estraggo i due Nonce e i due macAddress
	AA = p1.src
	SPA = p2.src
	ANonce = getEapolKeyPart(p1).Nonce	
	SNonce = getEapolKeyPart(p2).Nonce
	
	#genero le chiavi di sessione
	keyGen = keyGenerator(psk,mex,AA,SPA,ANonce,SNonce)
	[kck,kek,tk,authenticatorMicKey,supplicantMicKey] = keyGen.getKeys()
	#print ':'.join('%02x' % ord(b) for b in kck)
	
	#prendo il pacchetto p3, e ne faccio il parsing
	packetHandler = pcap.pcapObject()
	packetHandler.open_offline('../pacchetti-catturati/'+'four_way_3')	
	packet = packetHandler.next()
	(pktlen, data, timestamp) = packet
	# creo l'oggetto dal campo data	e stampo il pacchetto
	packetSplitter = Splitter(data)			
	packet3Obj = packetSplitter.get_packet_splitted()

	#calcolo il MIC del pacchetto 3
	cryptoMgm = cryptoManager(packet,packet3Obj,kek,kck)
	mic = cryptoMgm.getMic()
	
	#print mic_original
	print getEapolKeyPart(p3).mic
	print mic


except PacketError as (error,mex):
	#Errori sui pacchetti in input
	print 'ERRORS in input packets'
	print mex
	print 'closing program'






















