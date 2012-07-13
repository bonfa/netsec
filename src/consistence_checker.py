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
		Ritorna true se 
		'''
		p1_consistence = self.firstPacketCosistent
		p2_consistence = self.secondPacketCosistent
		p3_consistence = self.thirdPacketCosistent	
		p4_consistence = self.fourthPacketCosistent
		return (p1_consistence and p2_consistence and p3_consistence and p4_consistence)
