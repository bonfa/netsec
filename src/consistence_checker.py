#/usr/bin/python
# -*- coding: utf-8 -*-

'''
Modulo che si occupa di controllare se i pacchetti sono coerenti
'''


class FourWayHandshakeConsistenceChecker():
	'''
	Riceve in ingresso 4 pacchetti e e determina se sono i quattro pacchetti del fourway handshake
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
		p1_consistence = self.firstPacketCosistent()
		p2_consistence = self.secondPacketCosistent()
		p3_consistence = self.thirdPacketCosistent()	
		p4_consistence = self.fourthPacketCosistent()
		packets_address_consistence = self.macAddressConsistence()
		return (p1_consistence and p2_consistence and p3_consistence and p4_consistence and packets_address_consistence)

		
	
	def firstPacketCosistent(self):
		'''
		Ritorna true se i test di consistenza hanno successo sul primo pacchetto
		'''
		return self.checkPacketConsistence(self.packet_1,self.packet_1_correct_parameters)
	
	
	
	def secondPacketCosistent(self):
		'''
		Ritorna true se i test di consistenza hanno successo sul secondo pacchetto
		'''
		return self.checkPacketConsistence(self.packet_2,self.packet_2_correct_parameters)
	
	
	
	def thirdPacketCosistent(self):
		'''
		Ritorna true se i test di consistenza hanno successo sul terzo pacchetto
		'''
		return self.checkPacketConsistence(self.packet_3,self.packet_3_correct_parameters)
	
	
	
	def fourthPacketCosistent(self):
		'''
		Ritorna true se i test di consistenza hanno successo sul quarto pacchetto
		'''
		return self.checkPacketConsistence(self.packet_4,self.packet_4_correct_parameters)
	
	
	
	def macAddressConsistence(self):
		'''
		Ritorna true se i test di consistenza sui mac address hanno successo
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
		
		return True
		
		
		
	@Classmethod	
	def checkPacketConsistence(self,real_packet,correct_parameter):
		'''
		Ritorna true se i parametri del pacchetto corrispondono a quelli corretti
		'''
		
		
		
		
		
		
		
	