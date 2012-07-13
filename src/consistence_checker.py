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
	
	def secondPacketCosistent(self):
		'''
		Ritorna true se i test di consistenza hanno successo sul secondo pacchetto
		'''
	
	def thirdPacketCosistent(self):
		'''
		Ritorna true se i test di consistenza hanno successo sul terzo pacchetto
		'''
	
	
	def fourthPacketCosistent(self):
		'''
		Ritorna true se i test di consistenza hanno successo sul quarto pacchetto
		'''
	
	
	def macAddressConsistence(self):
		'''
		Ritorna true se i test di consistenza sui mac address hanno successo
		'''
	