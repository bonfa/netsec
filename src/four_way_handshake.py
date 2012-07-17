#/usr/bin/python
# -*- coding: utf-8 -*-

'''
Modulo che riceve i nomi dei quattro pacchetti del 4 way handshake, ne estrae i nonces e gli indirizzi, calcola le chiavi e si occupa di controllare il MIC sui pacchetti del fourway handshake
'''

#from packet_subfields import *
#import sys
#sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src/utilities')
#from exception import PacketError
from pack import Pacchetto
from consistence_checker import FourWayHandshakeConsistenceChecker
from packet_parser import Splitter
import pcap
from four_way_crypto_utility import passphraseToPSKMap,keyGenerator,cryptoManager


class FourWayHandshakeManager():


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
	


	def getSessionKeys():
		'''
		Ritorna la tk, authenticatorMicKey e supplicantMicKey
		'''
		return self.tk,self.authenticatorMicKey,self.supplicantMicKey



	def checkMacAddresses(self):
		'''
		Controlla che i mac address siano corrispondenti
		'''
		#definisco il controllore di pacchetti
		controlloreErrori = FourWayHandshakeConsistenceChecker(self.p1.scapyForm,self.p2.scapyForm,self.p3.scapyForm,self.p4.scapyForm)
		#controlla la coerenza sui mac_addres
		controlloreErrori.macAddressConsistence()		
		


	def checkMics(self):
		'''
		Controlla che i MIC dei pacchetti 2,3 e 4 siano corretti
		'''
		packet_list = [self.p2,self.p3,self.p4]
		for packet in packet_list:
			# prendo il pacchetto e ne calcolo il MIC
			micGen = cryptoManager(packet.pcapForm,packet.objectForm,kek,kck)
			# ottengo il mic
			mic_generato = micGen.getMic()	
			# controllo che il mic calcolato sia uguale al mic mandato	
			if mic_generato != packet.object.payload.payload.key_mic:
				raise PacketError('mic_generato != packet.object.payload.payload.key_mics','MIC generato diverso dal MIC del pacchetto')


	
	def getAbnormalities(self):
		'''
		Se c'è qualche campo che non rispetta le specifiche, ritorna un messaggio contenente le anormalità nei pacchetti
		'''
		#definisco il controllore di pacchetti
		controlloreErrori = FourWayHandshakeConsistenceChecker(self.p1.scapyForm,self.p2.scapyForm,self.p3.scapyForm,self.p4.scapyForm)
		#ritorno le anormalità nei pacchetti
		return controlloreErrori.getAbnormalities()
		


	def generateKeys(self):
		'''
		Genera le chiavi a partire dai pacchetti
		'''
		#genero psk a partire dal pms (pre master secret) e dall'SSID
		pskGenerator = passphraseToPSKMap(self.pms,self.ssid)
		psk = pskGenerator.getPsk()

		#estraggo i due Nonce e i due macAddress
		ANonce = self.p1.objectForm.payload.payload.key_nonce
		SNonce = self.p2.objectForm.payload.payload.key_nonce
		AA = self.p1.objectForm.header.source_address
		SPA = self.p2.objectForm.header.destination_address

		#genero le chiavi di sessione
		keyGen = keyGenerator(psk,mex,AA,SPA,ANonce,SNonce)
		[kck,kek,tk,authenticatorMicKey,supplicantMicKey] = keyGen.getKeys()
		self.kck = kck
		self.kek = kek
		self.tk = tk
		self.authenticatorMicKey = authenticatorMicKey
		self.supplicantMicKey = supplicantMicKey


	def setPackets(self):
		'''
		Legge i quattro pacchetti del 4 way handshake e crea le strutture pacchetto
		'''
		p1pcap,p1object,p1scapy = getObjectPacket(self.p_1_name)
		p1 = Pacchetto(p1pcap,p1object,p1scapy)

		p2pcap,p2object,p2scapy = getObjectPacket(self.p_2_name)
		p2 = Pacchetto(p2pcap,p2object,p2scapy)		

		p3pcap,p3object,p3scapy = getObjectPacket(self.p_3_name)
		p3 = Pacchetto(p3pcap,p3object,p3scapy)
		
		p4pcap,p4object,p4scapy = getObjectPacket(self.p_4_name)
		p4 = Pacchetto(p4pcap,p4object,p4scapy)
		


	@classmethod
	def getObjectPacket(filename):
	'''
	A partire dal nome del pacchetto ritorna il pacchetto, l'oggetto splittato grazie a Splitter e l'oggetto Scapy
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
			return original_format,packetSplitter.get_packet_splitted(),scapy_packet
		else:
			raise noPacketRead('packet_list.next()!= None','No packets found in input')




