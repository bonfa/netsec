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



	def checkPackets(self):
		'''
		Controlla che i pacchetti del fourway handshake siano coerenti.
		Se c'è qualche cosa strana ritorna un messaggio contenente le anormalità
		'''
		#definisco il controllore di pacchetti
		controlloreErrori = FourWayHandshakeConsistenceChecker(self.p1.scapyForm,self.p2.scapyForm,self.p3.scapyForm,self.p4.scapyForm)
		#controlla la coerenza sui mac_addres
		controlloreErrori.macAddressConsistence()		
		#ritorno le anormalità nei pacchetti
		return abnormalities = controlloreErrori.getAbnormalities()
		
	
	def generateKeys(self):
		'''
		'''
	


	def setPackets(self):
		'''
		Legge i quattro pacchetti del 4 way handshake e creo le strutture pacchetto
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


