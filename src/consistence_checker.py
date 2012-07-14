#/usr/bin/python
# -*- coding: utf-8 -*-

'''
Modulo che si occupa di controllare se i pacchetti sono coerenti
'''


class FourWayHandshakeConsistenceChecker():
	'''
	Riceve in ingresso 4 pacchetti e e determina se sono i quattro pacchetti del fourway handshake e se sono coerenti
	'''
	def __init__(self,p1,p2,p3,p4):
		self.packet_1 = p1
		self.packet_2 = p2
		self.packet_3 = p3
		self.packet_4 = p4
		self.packet_1_correct_parameters = ;
		self.packet_2_correct_parameters = ;
		self.packet_3_correct_parameters = ;
		self.packet_4_correct_parameters = ;

		
		
	def isConsistent(self):
		'''
		Ritorna true se tutti i test di consistenza hanno successo
		'''
		self.firstPacketCosistent()
		self.secondPacketCosistent()
		self.thirdPacketCosistent()	
		self.fourthPacketCosistent()
		self.macAddressConsistence()
		return True

		
	
	def firstPacketCosistent(self):
		'''
		Esegue i test di consistenza sul primo pacchetto
		'''
		self.checkPacketConsistence(self.packet_1,self.packet_1_correct_parameters)
	
	
	
	def secondPacketCosistent(self):
		'''
		Esegue i test di consistenza sul secondo pacchetto
		'''
		self.checkPacketConsistence(self.packet_2,self.packet_2_correct_parameters)
	
	
	
	def thirdPacketCosistent(self):
		'''
		Esegue i test di consistenza sul terzo pacchetto
		'''
		self.checkPacketConsistence(self.packet_3,self.packet_3_correct_parameters)
	
	
	
	def fourthPacketCosistent(self):
		'''
		Esegue i test di consistenza sul quarto pacchetto
		'''
		self.checkPacketConsistence(self.packet_4,self.packet_4_correct_parameters)
	
	
	
	def macAddressConsistence(self):
		'''
		Esegue i test di consistenza sui mac address
		'''
		#Controllo gli indirizzi del primo e del terzo pacchetto
		if self.packet_1.src != self.packet_3.src
			raise PacketError('self.packet_1.src != self.packet_3.src','Different source address')
				
		if self.packet_1.dst != self.packet_3.dst
			raise PacketError('self.packet_1.dst != self.packet_3.dst','Different destination address')
		
		#Controllo gli indirizzi del secondo e del quarto pacchetto	
		if self.packet_2.src != self.packet_4.src
			raise PacketError('self.packet_2.src != self.packet_4.src','Different source address')
		if self.packet_2.dst != self.packet_4.dst
			raise PacketError('self.packet_2.dst != self.packet_4.dst','Different destination address')
			
		#Controllo che l'indirizzo sorgente del primo pacchetto corrisponda all'indirizzo destinazione del secondo 
		if self.packet_1.src != self.packet_2.dst
			raise PacketError('self.packet_1.src != self.packet_2.dst','Addresses must be equal')
		if self.packet_2.src != self.packet_1.dst
			raise PacketError('self.packet_2.src != self.packet_1.dst','Addresses must be equal')	
		
		
		
	@Classmethod	
	def checkPacketConsistence(self,real_packet,correct_parameter):
		'''
		Ritorna true se i parametri del pacchetto corrispondono a quelli corretti
		'''
		
		
		
		
		
		
		
	
