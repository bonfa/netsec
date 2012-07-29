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
import time
from datetime import datetime, date, time
from scapy.all import *
from wpa_struct_for_scapy import *
from packet_printer import stringInHex
from packet_subfields import getEapolKeyPart,printPacket
from four_way_handshake import FourWayHandshakeManager
from four_way_handshake_v2 import FourWayHandshakeManagerWithScapyOnly
import binascii
from exception import PacketError,TKIPError,MacError
from tkip import TkipDecryptor


class Main():

	def __init__(self,pms,ssid,path1,path2,path3,path4,dataPath):
		#definisco le variabili principali
		self.NomePacchetto1_4Way = path1
		self.NomePacchetto2_4Way = path2
		self.NomePacchetto3_4Way = path3
		self.NomePacchetto4_4Way = path4
		self.pms = pms
		self.ssid = ssid
		self.criptedPacketListName = dataPath
		self.authenticatorAddressTuple = self.getAuthenticatorAddress()
		self.supplicantAddressTuple = self.getSupplicantAddress()



	def print4WayHandshakeWarning(self,mex):
		'''	
		stampa il messaggio di warning dei pacchetti in ingresso
		'''
		if mex != '':
			print "WARNING: abnormalities in the 4 way handshake input packets. The program will try to continue the execution. (Abnormalities are listed in 'abnormalities.txt')"
			# Scrive un file.
			today = datetime.now()
			out_file = open("abnormalities.txt","w")
			out_file.write('[DATE]: ' + str(today.year)+'-'+str(today.month)+'-'+str(today.day)+3*' '+str(today.hour)+':'+str(today.minute)+':'+str(today.second)+'\n')
			out_file.write('[4_WAY_FILE_1]: ' + self.NomePacchetto1_4Way+'\n')
			out_file.write('[4_WAY_FILE_2]: ' + self.NomePacchetto2_4Way+'\n')			
			out_file.write('[4_WAY_FILE_3]: ' + self.NomePacchetto3_4Way+'\n')			
			out_file.write('[4_WAY_FILE_4]: ' + self.NomePacchetto4_4Way+'\n\n')				
			out_file.write('[DATA_FILE]: ' + self.criptedPacketListName +'\n')
			out_file.write('[ABNORMALITIES]:\n')
			out_file.write(mex)
			out_file.close()



	def doFourWayHandshake(self,NomePacchetto1_4Way,NomePacchetto2_4Way,NomePacchetto3_4Way,NomePacchetto4_4Way,pms,ssid):
		'''
		Effettua tutte le operazioni in ordine del fourwayhandshake
		'''
		#carico il pacchetto 1 del 4way
		packet = self.loadSessionPacket(self.NomePacchetto1_4Way)[0]
		if packet.payload.name == '802.11':		
			#definisco l'oggetto che si occupa di caricare i pacchetti del fourwayhandshake e creare le chiavi
			fourWayManager = FourWayHandshakeManagerWithScapyOnly(NomePacchetto1_4Way,NomePacchetto2_4Way,NomePacchetto3_4Way,NomePacchetto4_4Way,pms,ssid)		
		else:
			#definisco l'oggetto che si occupa di caricare i pacchetti del fourwayhandshake e creare le chiavi
			fourWayManager = FourWayHandshakeManager(NomePacchetto1_4Way,NomePacchetto2_4Way,NomePacchetto3_4Way,NomePacchetto4_4Way,pms,ssid)
		#controlla i mac_address
		fourWayManager.checkMacAddresses()
		#controlla i mic
		fourWayManager.checkMics()
		#ritorna le anormalità nei pacchetti
		abnormalities = fourWayManager.getAbnormalities()
		#stampa le abnormalità nei pacchetti se ci sono
		self.print4WayHandshakeWarning(abnormalities)
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
		trasmitterMacAddressTuple = self.getTrasmitterMacAddr(packet)
		if (trasmitterMacAddressTuple == self.authenticatorAddressTuple):
			return authenticatorMicKey 
		elif (trasmitterMacAddressTuple == self.supplicantAddressTuple):	
			return supplicantMicKey 
		else:
			raise MacError('','trasmission address different both from authenticatorAddress and supplicantAddress')



	def getTrasmitterMacAddr(self,packet):
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




	def getAuthenticatorAddress(self):
		'''
		Estrae dal pacchetto scapy la stringa del src_address e la ritorna
		'''
		packet = self.loadSessionPacket(self.NomePacchetto1_4Way)[0]
		if packet.payload.name == '802.11':
			toDsFromDs = packet.FCfield & 0x3
			if toDsFromDs==0 or toDsFromDs==1:
				macAddrScapy = str(packet.addr2)
			elif toDsFromDs==2:
				macAddrScapy = str(packet.addr3)
			elif toDsFromDs==3:
				macAddrScapy = str(packet.addr4)
			else:
				raise TKIPError('toDsFromDs not in (0,1,2,3)','Error in flags')
			return self.getAddrTuple(macAddrScapy)
		elif packet.name == 'Ethernet':
			macAddrScapy = packet.src
			return self.getAddrTuple(macAddrScapy)
		else:
			raise PacketError('nor 802.11 and Ethernet in packet','Unable to load mac addresses')



	def getSupplicantAddress(self):
		'''
		Estrae dal pacchetto scapy la stringa del dst_address e la ritorna
		'''
		packet = self.loadSessionPacket(self.NomePacchetto1_4Way)[0]
		if packet.payload.name == '802.11':
			toDsFromDs = packet.FCfield & 0x3
			if toDsFromDs==0 or toDsFromDs==2:
				macAddrScapy = str(packet.addr1)
			elif toDsFromDs==1 or toDsFromDs==3:
				macAddrScapy = str(packet.addr3)
			else:
				raise MacError('toDsFromDs not in (0,1,2,3)','Error in flags')
			return self.getAddrTuple(macAddrScapy)
		elif packet.name == 'Ethernet':
			macAddrScapy = packet.dst
			return self.getAddrTuple(macAddrScapy)
		else:
			raise PacketError('nor 802.11 and Ethernet in packet','Unable to load mac addresses')



	def getAddrTuple(self,macAddrScapy):
		'''
		Riceve in input un indirizzo scapy e torna la tupla corrispondente
		'''
		macAddrTuple = (macAddrScapy).split(':')
		macIntegerList = []
		for i in range(len(macAddrTuple)):
			macIntegerList.append(int(macAddrTuple[i],16))
		i1,i2,i3,i4,i5,i6 = macIntegerList
		return (i1,i2,i3,i4,i5,i6)




	def execute(self):
		# 4 way handshake	
		tk,authenticatorMicKey,supplicantMicKey = self.doFourWayHandshake(self.NomePacchetto1_4Way,self.NomePacchetto2_4Way,self.NomePacchetto3_4Way,self.NomePacchetto4_4Way,self.pms,self.ssid)
		
		#self.printKeys(tk,authenticatorMicKey,supplicantMicKey)

		# load session packets
		criptedPacketList = self.loadSessionPacket(self.criptedPacketListName)

		decryptedList = []
		decriptati = 0
		nonDecriptati = 0

		for i in range(len(criptedPacketList)):
			try:
				dataPack = criptedPacketList[i]
				# provo a decriptarlo con le chiavi
				decrypted = self.getDecriptedPacket(dataPack,tk,authenticatorMicKey,supplicantMicKey)
				decryptedList.append(decrypted)
				decriptati = decriptati + 1
			except Exception as e:
				nonDecriptati = nonDecriptati + 1 

		# salvo la lista di pacchetti decriptati in un file pcap
		if len(decryptedList)!= 0:
			wrpcap(self.criptedPacketListName[:-5]+'-dec.pcap',decryptedList)
		
		# stampo un breve report
		print "[RESULTS]"
		print '  ' + 'Total number of packets read = ' + str(len(criptedPacketList))
		print '  ' + 'Number of decrypted packets = ' + str(decriptati)
		print '  ' + 'Number of non-decrypted packets = ' + str(nonDecriptati)



if __name__ == '__main__':
	if len(sys.argv) != 8:
		print "Wrong parameters number"
		print "Input parameters must be as follows:"
		print 2*' ' + 'pms'
		print 2*' ' + 'ssid'
		print 2*' ' + 'four_way_handshake_message_1_path'
		print 2*' ' + 'four_way_handshake_message_2_path'
		print 2*' ' + 'four_way_handshake_message_3_path'
		print 2*' ' + 'four_way_handshake_message_4_path'
		print 2*' ' + 'pcap_file_path'
		sys.exit()
	else:
		pms,ssid,path1,path2,path3,path4,dataPath = sys.argv[1:]
		m = Main(pms,ssid,path1,path2,path3,path4,dataPath)
		m.execute()





