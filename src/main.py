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
from wpa_struct_for_scapy import *
from packet_printer import stringInHex
from packet_subfields import getEapolKeyPart,printPacket
from four_way_handshake import FourWayHandshakeManager
import binascii
from exception import PacketError



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
	print "tk = " + binascii.hexlify(tk)
	print "authMICKey = " + binascii.hexlify(authenticatorMicKey)
	print "supplMicKey = " + binascii.hexlify(supplicantMicKey)



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




#definisco le variabili principali
path = '../pacchetti-catturati/'
NomePacchetto1_4Way = path + 'four_way_1'
NomePacchetto2_4Way = path + 'four_way_2'
NomePacchetto3_4Way = path + 'four_way_3'
NomePacchetto4_4Way = path + 'four_way_4'
groupKeyHandshakeMsg1Name = path + 'group_key_1'
groupKeyHandshakeMsg2Name = path + 'group_key_2'
pms = 'H6x&@!1uLQ*()!12c0x\\f^\'?|s<SNgh-'
ssid = 'WWWLAN'
criptedPacketListName = path + 'ultimo/fish0all'
clearPacketListName = path + 'ultimo/wlan0tcp80'


try:
	# 4 way handshake	
	tk,authenticatorMicKey,supplicantMicKey = doFourWayHandshake(NomePacchetto1_4Way,NomePacchetto2_4Way,NomePacchetto3_4Way,NomePacchetto4_4Way,pms,ssid)
	
	#stampo le chiavi di sessione ottenute
	printKeys(tk,authenticatorMicKey,supplicantMicKey)
	print ""
	
	# load session packets
	criptedPacketList = loadSessionPacket(criptedPacketListName)

	# stampo i pacchetti con scapy
	#criptedPacketList.show()
	
	# prendo il primo pacchetto che sicuramente è un pacchetto dati
	dataPack = criptedPacketList[1]
	# provo a decriptarlo con le chiavi
	decrypted = getDecriptedPacket(dataPack,tk,authenticatorMicKey,supplicantMicKey)	



except PacketError as (error,mex):
	#Errori sui pacchetti in input
	print 'ERRORS in input packets'
	print mex
	print 'closing program'






















