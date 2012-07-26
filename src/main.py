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
from exception import PacketError,TKIPError,MacError
from tkip import TkipDecryptor


class Main():

	def __init__(self):
		#definisco le variabili principali
		self.path = '../pacchetti-catturati/ultimo/'
		self.NomePacchetto1_4Way = self.path + 'four_way_1'
		self.NomePacchetto2_4Way = self.path + 'four_way_2'
		self.NomePacchetto3_4Way = self.path + 'four_way_3'
		self.NomePacchetto4_4Way = self.path + 'four_way_4'
		self.pms = 'H6x&@!1uLQ*()!12c0x\\f^\'?|s<SNgh-'
		self.ssid = 'WWWLAN'
		self.criptedPacketListName = self.path + 'fish0all'
		self.clearPacketListName = self.path + 'wlan0tcp80'
		self.authenticatorAddressTuple = (0x00,0x18,0xe7,0x45,0x0e,0x22)		
		self.supplicantAddressTuple = (0x00,0x19,0xd2,0x4a,0x39,0xb8)


	def print4WayHandshakeWarning(self,mex):
		'''	
		stampa il messaggio di warning dei pacchetti in ingresso
		'''
		if mex != '':
			print 'WARNING: abnormalities in the input packets:'
			print mex
			print 'The program will try to continue the execution'



	def doFourWayHandshake(self,NomePacchetto1_4Way,NomePacchetto2_4Way,NomePacchetto3_4Way,NomePacchetto4_4Way,pms,ssid):
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
		self.print4WayHandshakeWarning(abnormalities)

		print "[4 WAY HANDSHAKE SUCCESSFULL]"
		#prendo le chiavi di sessione
		return fourWayManager.getSessionKeys()



	def printKeys(self,tk,authenticatorMicKey,supplicantMicKey):
		'''
		Stampa le chiavi di sessione ottenute dal 4 way handshake
		'''
		print "\n [KEYS]:"
		print "tk = " + str(struct.unpack('16B',tk[:16]))
		print "tk = " + binascii.hexlify(tk)
		print "authMICKey = " + binascii.hexlify(authenticatorMicKey)
		print "supplMicKey = " + binascii.hexlify(supplicantMicKey)
		print ""



	def loadSessionPacket(self,PacketListName):
		'''
		Ritorna la lista dei pacchetti catturati. I pacchetti vengono letti grazie a scapy da un file pcap
		'''
		#leggo i pacchetti con scapy
		packetList = rdpcap(PacketListName)
		return packetList



	def getDecriptedPacket(self,criptedPacket,temporalKey,authenticatorMicKey,supplicantMicKey):
		'''
		Prende in ingresso un pacchetto criptato e lo decripta
		'''
		micKey = self.getProperMicKey(criptedPacket,authenticatorMicKey,supplicantMicKey)
		decryptor = TkipDecryptor(criptedPacket,temporalKey,micKey)
		plaintext = decryptor.getDecryptedPacket()
		return plaintext	
	

	def getProperMicKey(self,packet,authenticatorMicKey,supplicantMicKey):
		'''
		Ritorna la chiave corretta per il calcolo del mic in funzione del mittente del pacchetto
		'''
		trasmitterMacAddressTuple = self.getSrcAddress(packet)
		if (trasmitterMacAddressTuple == self.authenticatorAddressTuple):
			return authenticatorMicKey
		elif (trasmitterMacAddressTuple == self.supplicantAddressTuple):	
			return supplicantMicKey
		else:
			raise MacError('','trasmission address different both from authenticatorAddress and supplicantAddress')


	def getSrcAddress(self,packet):
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

	def execute(self):
		# 4 way handshake	
		tk,authenticatorMicKey,supplicantMicKey = self.doFourWayHandshake(self.NomePacchetto1_4Way,self.NomePacchetto2_4Way,self.NomePacchetto3_4Way,self.NomePacchetto4_4Way,self.pms,self.ssid)

		#stampo le chiavi di sessione ottenute
		self.printKeys(tk,authenticatorMicKey,supplicantMicKey)


		# load session packets
		criptedPacketList = self.loadSessionPacket(self.criptedPacketListName)

		# stampo i pacchetti con scapy
		criptedPacketList.show()

		# prendo il secondo pacchetto che sicuramente è un pacchetto dati
		#indexListFrom_1 = (5,6)
		#indexListFrom_0 = []
		#for j in range(len(indexListFrom_1)):
		#	indexListFrom_0.append(indexListFrom_1[j] - 1)

		#for i in indexListFrom_0:
		try:
			#print i
			dataPack = criptedPacketList[10]
			dataPack.show()	
			# provo a decriptarlo con le chiavi
			decrypted = self.getDecriptedPacket(dataPack,tk,authenticatorMicKey,supplicantMicKey)
			print "TKIP MIC OK"
		except TKIPError:
			print "TKIP MIC ERROR"
			exit(-1)

		#stampo il pacchetto decriptato
		print "END"
		#decrypted.show()	

		#except PacketError as (error,mex):
			#Errori sui pacchetti in input
		#	print 'ERRORS in input packets'
		#	print mex
		#	print 'closing program'
	


if __name__ == '__main__':
	m = Main()
	m.execute()





