#/usr/bin/python
# -*- coding: utf-8 -*-

'''
Modulo che riceve i nomi dei quattro pacchetti del 4 way handshake, ne estrae i nonces e gli indirizzi, calcola le chiavi e si occupa di controllare il MIC sui pacchetti del fourway handshake
'''

#from packet_subfields import *
import sys
sys.path.append('../utilities')
sys.path.append('../packetStruct')
from exception import PacketError
from pack import Pacchetto
from consistence_checker import FourWayHandshakeConsistenceChecker
from packet_parser import Splitter
import pcap
from four_way_crypto_utility import passphraseToPSKMap,keyGenerator,cryptoManager
from scapy.all import *
import packet_printer
from wpa_struct_for_scapy import *



class FourWayHandshakeManagerWithScapyOnly():


	def __init__(self,p1name,p2name,p3name,p4name,pms,ssid):
		self.p_1_name = p1name
		self.p_2_name = p2name
		self.p_3_name = p3name
		self.p_4_name = p4name
		self.pms = pms
		self.ssid = ssid
		self.mex = "Pairwise key expansion"
		self.p1 = None
		self.p2 = None
		self.p3 = None
		self.p4 = None
		self.setPackets()
		self.kck = None
		self.kek = None
		self.tk = None 
		self.authenticatorMicKey= None
		self.supplicantMicKey = None
		self.generateKeys()
	


	def getSessionKeys(self):
		'''
		Ritorna la tk, authenticatorMicKey e supplicantMicKey
		'''
		return self.tk,self.authenticatorMicKey,self.supplicantMicKey



	def checkMacAddresses(self):
		'''
		Controlla che i mac address siano corrispondenti
		'''
		#definisco il controllore di pacchetti
		#controlloreErrori = FourWayHandshakeConsistenceChecker(self.p1.scapyForm,self.p2.scapyForm,self.p3.scapyForm,self.p4.scapyForm)
		#controlla la coerenza sui mac_addres
		#controlloreErrori.macAddressConsistence()		
		


	def checkMics(self):
		'''
		Controlla che i MIC dei pacchetti 2,3 e 4 siano corretti
		@TODO: implementare il metodo
		'''
		


	
	def getAbnormalities(self):
		'''
		Se c'è qualche campo che non rispetta le specifiche, ritorna un messaggio contenente le anormalità nei pacchetti
		@TODO: implementare il metodo
		'''
		#definisco il controllore di pacchetti
		controlloreErrori = FourWayHandshakeConsistenceChecker(self.p1.scapyForm,self.p2.scapyForm,self.p3.scapyForm,self.p4.scapyForm)
		#ritorno le anormalità nei pacchetti
		return controlloreErrori.getAbnormalities()
		#return ''


	def generateKeys(self):
		'''
		Genera le chiavi a partire dai pacchetti
		'''
		#genero psk a partire dal pms (pre master secret) e dall'SSID
		pskGenerator = passphraseToPSKMap(self.pms,self.ssid)
		psk = pskGenerator.getPsk()

		#print 'PMK = ' + str(packet_printer.stringInHex(psk))
		#estraggo i due Nonce e i due macAddress
		ANonce = self.getNonce(self.p1.scapyForm)
		SNonce = self.getNonce(self.p2.scapyForm)
		AA = self.getSrcAddress(self.p1.scapyForm)
		SPA = self.getSrcAddress(self.p2.scapyForm)

		#print 'AN = ' + ANonce
		#print 'SN = ' + SNonce
		#print 'AA = ' + str(AA)
		#print 'SA = ' + str(SPA)
		#genero le chiavi di sessione
		keyGen = keyGenerator(psk,self.mex,AA,SPA,ANonce,SNonce)
		[kck,kek,tk,authenticatorMicKey,supplicantMicKey] = keyGen.getKeys()
		self.kck = kck
		self.kek = kek
		self.tk = tk
		self.authenticatorMicKey = authenticatorMicKey
		self.supplicantMicKey = supplicantMicKey




	@classmethod
	def getNonce(self,scapyPacket):
		'''
		Estrae il nonce a partire dal pacchetto scapy
		'''
		nonceStr = scapyPacket.Nonce
		return nonceStr



	@classmethod
	def getSrcAddress(self,packet):
		'''
		Estrae dal pacchetto scapy la stringa del src_address e la ritorna
		'''
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
			return self.getAddrStr(macAddrScapy)
		else:
			raise PacketError('nor 802.11 layer in packet','Unable to load mac addresses')


	
	@classmethod
	def getAddrStr(self,macAddrScapy):
		'''
		Riceve in input un indirizzo scapy e torna la tupla corrispondente
		'''
		macAddrTuple = (macAddrScapy).split(':')
		macIntegerList = []
		for i in range(len(macAddrTuple)):
			macIntegerList.append(int(macAddrTuple[i],16))
		i1,i2,i3,i4,i5,i6 = macIntegerList
		return struct.pack('6B',i1,i2,i3,i4,i5,i6)

		


	def setPackets(self):
		'''
		Legge i quattro pacchetti del 4 way handshake e crea le strutture pacchetto
		'''
		p1pcap,p1object,p1scapy = self.getObjectPacket(self.p_1_name)
		self.p1 = Pacchetto(p1pcap,p1object,p1scapy)
		
		p2pcap,p2object,p2scapy = self.getObjectPacket(self.p_2_name)
		self.p2 = Pacchetto(p2pcap,p2object,p2scapy)		
	
		p3pcap,p3object,p3scapy = self.getObjectPacket(self.p_3_name)
		self.p3 = Pacchetto(p3pcap,p3object,p3scapy)
		
		p4pcap,p4object,p4scapy = self.getObjectPacket(self.p_4_name)
		self.p4 = Pacchetto(p4pcap,p4object,p4scapy)
		
		


	@classmethod
	def getObjectPacket(self,filename):
		'''
		Ritorna la lista dei pacchetti catturati. I pacchetti vengono letti grazie a scapy da un file pcap
		'''
		packet = rdpcap(filename)[0]
		return packet



	
	@classmethod
	def getObjectPacket(self,filename):
		'''
		A partire dal nome del pacchetto ritorna il pacchetto, (None) e l'oggetto Scapy
		@todo: controllare l'input del pacchetto nel caso della lettura con scapy
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
				(pktlen, original_format, timestamp) = packet
				# Creo l'oggetto che splitta il file
				packetSplitter = Splitter(original_format)			
				# Leggo il file tramite scapy e ritorno l'oggetto scapy (rdpcap torna una lista e quindi devo prendere il primo elemento)
				scapy_packet = rdpcap(filename)[0] 
				# Ritorno l'oggetto
				return original_format,None,scapy_packet
			else:
				raise noPacketRead('packet_list.next()!= None','No packets found in input')

