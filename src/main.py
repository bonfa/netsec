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
from packet_subfields import getEapolKeyPart,printPacket

from four_way_crypto_utility import passphraseToPSKMap,keyGenerator,cryptoManager
from exception import PacketError
from packet_parser import Splitter


def print4WayHandshakeWarning(mex):
	'''	
	stampa il messaggio di warning dei pacchetti in ingresso
	'''
	if mex != '':
		print 'WARNING: abnormalities in the input packets:'
		print mex
		print 'The program will try to continue the execution'


#definisco le variabili principali
path = '../pacchetti-catturati/'
NomeDelPacchetto1DelFourWayHandshake = path + 'four_way_1'
NomeDelPacchetto2DelFourWayHandshake = path + 'four_way_2'
NomeDelPacchetto31DelFourWayHandshake = path + 'four_way_3'
NomeDelPacchetto4DelFourWayHandshake = path + 'four_way_4'
groupKeyHandshakeMsg1Name = path + 'group_key_1'
groupKeyHandshakeMsg2Name = path + 'group_key_2'
pms = 'H6x&@!1uLQ*()!12c0x\\f^\'?|s<SNgh-'
ssid = 'WWWLAN'



try:
	FourWayHandshakeManager(NomeDelPacchetto1DelFourWayHandshake)
	#definisco il controllore di pacchetti
	controlloreErrori = FourWayHandshakeConsistenceChecker(scapy_p1,scapy_p2,scapy_p3,scapy_p4)
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
	ANonce = oggetto1Del4WayHandshake.payload.payload.key_nonce
	SNonce = oggetto2Del4WayHandshake.payload.payload.key_nonce
	AA = oggetto1Del4WayHandshake.header.source_address
	SPA = oggetto1Del4WayHandshake.header.destination_address
	
	#genero le chiavi di sessione
	keyGen = keyGenerator(psk,mex,AA,SPA,ANonce,SNonce)
	[kck,kek,tk,authenticatorMicKey,supplicantMicKey] = keyGen.getKeys()
	

except PacketError as (error,mex):
	#Errori sui pacchetti in input
	print 'ERRORS in input packets'
	print mex
	print 'closing program'






















