#/usr/bin/python
# -*- coding: utf-8 -*-

'''

'''

import sys
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src/utilities')
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src/common_utility')
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src/crypto')
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src/packetStruct')
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src/authentication')
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src')

# Set log level to benefit from Scapy warnings
import logging
logging.getLogger("scapy").setLevel(1)

from scapy.all import *
from wpa_struct_for_scapy import *
from packet_printer import stringInHex
from packet_subfields import getEapolKeyPart,printPacket
from four_way_handshake import FourWayHandshakeManager
import binascii
from exception import PacketError,TKIPError
from tkip import TkipDecryptor


def print4WayHandshakeWarning(mex):
	'''	
	stampa il messaggio di warning dei pacchetti in ingresso
	'''
	if mex != '':
		print 'WARNING: abnormalities in the input packets:'
		print mex
		print 'The program will try to continue the execution'



def doFourWayHandshake(NomePacchetto1_4Way,NomePacchetto2_4Way,NomePacchetto3_4Way,NomePacchetto4_4Way,pms,ssid):
	'''
	Effettua tutte le operazioni in ordine del fourwayhandshake
	'''		
	#definisco l'oggetto che si occupa di caricare i pacchetti del fourwayhandshake e creare le chiavi
	fourWayManager = FourWayHandshakeManager(NomePacchetto1_4Way,NomePacchetto2_4Way,NomePacchetto3_4Way,NomePacchetto4_4Way,pms,ssid)
	#Controllo i pacchetti
	#controlla i mac_address
	fourWayManager.checkMacAddresses()
	#controlla i mic
	fourWayManager.checkMics()
	#ritorna le anormalità nei pacchetti
	abnormalities = fourWayManager.getAbnormalities()
	#stampa le abnormalità nei pacchetti se ci sono
	print4WayHandshakeWarning(abnormalities)

	print "[4 WAY HANDSHAKE SUCCESSFULL]"
	#prendo le chiavi di sessione
	return fourWayManager.getSessionKeys()



def printKeys(tk,authenticatorMicKey,supplicantMicKey):
	'''
	Stampa le chiavi di sessione ottenute dal 4 way handshake
	'''
	print "\n [KEYS]:"
	print "tk = " + str(struct.unpack('16B',tk[:16]))
	print "tk = " + binascii.hexlify(tk)
	print "authMICKey = " + binascii.hexlify(authenticatorMicKey)
	print "supplMicKey = " + binascii.hexlify(supplicantMicKey)
	print ""



def loadSessionPacket(PacketListName):
	'''
	Ritorna la lista dei pacchetti catturati. I pacchetti vengono letti grazie a scapy da un file pcap
	'''
	#leggo i pacchetti con scapy
	packetList = rdpcap(PacketListName)
	return packetList



def getDecriptedPacket(criptedPacket,temporalKey,authenticatorMicKey,supplicantMicKey):
	'''
	Prende in ingresso un pacchetto criptato e lo decripta
	'''
	micKey = getProperMicKey(criptedPacket,authenticatorMicKey,supplicantMicKey)
	decryptor = TkipDecryptor(criptedPacket,temporalKey,micKey)
	plaintext = decryptor.getDecryptedPacket()
	return plaintext	
	

def getProperMicKey(packet,authenticatorMicKey,supplicantMicKey):
	'''
	Ritorna la chiave corretta per il calcolo del mic in funzione del mittente del pacchetto
	'''
	trasmitterMacAddressTuple = getSrcAddress(packet)
	if (trasmitterMacAddressTuple == authenticatorAddressTuple):
		return authenticatorMicKey
	else:	
		return supplicantMicKey


def getSrcAddress(packet):
	'''
	Estrae dal pacchetto scapy la stringa del src_address e ritorna la tupla
	'''
	macAddrScapy = str(packet.addr2)
	macAddrTuple = (macAddrScapy).split(':')
	macIntegerList = []
	for i in range(len(macAddrTuple)):
		macIntegerList.append(int(macAddrTuple[i],16))
	i1,i2,i3,i4,i5,i6 = macIntegerList
	return (i1,i2,i3,i4,i5,i6)


#definisco le variabili principali
path = '../pacchetti-catturati/ultimo/'
NomePacchetto1_4Way = path + 'four_way_1'
NomePacchetto2_4Way = path + 'four_way_2'
NomePacchetto3_4Way = path + 'four_way_3'
NomePacchetto4_4Way = path + 'four_way_4'
#groupKeyHandshakeMsg1Name = path + 'group_key_1'
#groupKeyHandshakeMsg2Name = path + 'group_key_2'
pms = 'H6x&@!1uLQ*()!12c0x\\f^\'?|s<SNgh-'
ssid = 'WWWLAN'
criptedPacketListName = path + 'fish0all'
clearPacketListName = path + 'wlan0tcp80'
authenticatorAddressTuple = (0x00,0x18,0xe7,0x45,0x0e,0x22)



try:
	# 4 way handshake	
	tk,authenticatorMicKey,supplicantMicKey = doFourWayHandshake(NomePacchetto1_4Way,NomePacchetto2_4Way,NomePacchetto3_4Way,NomePacchetto4_4Way,pms,ssid)
	
	#stampo le chiavi di sessione ottenute
	printKeys(tk,authenticatorMicKey,supplicantMicKey)

	
	# load session packets
	criptedPacketList = loadSessionPacket(criptedPacketListName)

	# stampo i pacchetti con scapy
	#criptedPacketList.show()
	
	# prendo il secondo pacchetto che sicuramente è un pacchetto dati
	indexListFrom_1 = (2,3)
	#indexListFrom_1 = (2,3,5,11,12,14,15,17,18,20,21,23,24,26,28,29,30)
	indexListFrom_0 = []
	for i in range(len(indexListFrom_1)):
		indexListFrom_0.append(indexListFrom_1[i] - 1)

	for i in indexListFrom_0:
		try:
			dataPack = criptedPacketList[i]
			#dataPack.show()	
			# provo a decriptarlo con le chiavi
			decrypted = getDecriptedPacket(dataPack[i],tk,authenticatorMicKey,supplicantMicKey)
			print "TKIP MIC OK"
		except TKIPError:
			print "TKIP MIC ERROR"

	#stampo il pacchetto decriptato
	print "END"
	#decrypted.show()	
	


except PacketError as (error,mex):
	#Errori sui pacchetti in input
	print 'ERRORS in input packets'
	print mex
	print 'closing program'
	





















