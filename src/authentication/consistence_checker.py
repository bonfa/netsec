#/usr/bin/python
# -*- coding: utf-8 -*-

'''
Modulo che si occupa di controllare se i pacchetti sono coerenti
@TODO: rifare tutta la gestione dei messaggi con delle liste
'''

from packet_subfields import *
import sys
sys.path.append('../utilities')
from exception import PacketError

tab = 4 * ' '

class FourWayHandshakeConsistenceChecker():
	'''
	Riceve in ingresso 4 pacchetti e e determina se sono i quattro pacchetti del fourway handshake e se sono coerenti
	Per tutti e quattro i pacchetti viene saltato il controllo del flag SM (che tanto è sempre settato a 0)
	'''
	def __init__(self,p1,p2,p3,p4):
		self.packet_1 = p1
		self.packet_2 = p2
		self.packet_3 = p3
		self.packet_4 = p4

	
	def macAddressConsistence(self):
		'''
		Esegue i test di consistenza sui mac address
		'''
		#Controllo gli indirizzi del primo e del terzo pacchetto
		if self.packet_1.src != self.packet_3.src:
			raise PacketError('self.packet_1.src != self.packet_3.src' , 'Different source address')
				
		if self.packet_1.dst != self.packet_3.dst:
			raise PacketError('self.packet_1.dst != self.packet_3.dst','Different destination address')
		
		#Controllo gli indirizzi del secondo e del quarto pacchetto	
		if self.packet_2.src != self.packet_4.src:
			raise PacketError('self.packet_2.src != self.packet_4.src','Different source address')
		if self.packet_2.dst != self.packet_4.dst:
			raise PacketError('self.packet_2.dst != self.packet_4.dst','Different destination address')
			
		#Controllo che l'indirizzo sorgente del primo pacchetto corrisponda all'indirizzo destinazione del secondo 
		if self.packet_1.src != self.packet_2.dst:
			raise PacketError('self.packet_1.src != self.packet_2.dst','Addresses must be equal')
		if self.packet_2.src != self.packet_1.dst:
			raise PacketError('self.packet_2.src != self.packet_1.dst','Addresses must be equal')
	

		
	def getAbnormalities(self):
		'''
		Ritorna un messaggio contenente le anormalità che i 4 pacchetti del 4way handshake presentano rispetto alle specifiche
		'''
		errorMex = '';
		
		firstMexErr = self.firstPacketErrors()
		if firstMexErr != '':
			errorMex += tab + 'packet 1:\n' + firstMexErr 
			
		secondMexErr = self.secondPacketErrors()
		if secondMexErr != '':
			errorMex += tab + 'packet 2:\n' + secondMexErr 

		thirdMexErr = self.thirdPacketErrors()
		if thirdMexErr != '':
			errorMex += tab + 'packet 3:\n' + thirdMexErr 

		fourthMexErr = self.fourthPacketErrors()
		if fourthMexErr != '':
			errorMex += tab + 'packet 4:\n' + fourthMexErr

		return errorMex

		
	
	def firstPacketErrors(self):
		'''
		Ritorna un messaggio contenete le anomalie che ha il primo pacchetto rispetto alle specifiche
		'''
		p1eapolKey = getEapolKeyPart(self.packet_1)
		err1Mex = ''				
		#Controlli
		#Bit secure
		if getSecureFlag(p1eapolKey) != 0:
			err1Mex += 2*tab + 'secure flag must be 0\n'

		#MIC_flagscapy 
		if getMicFlag(p1eapolKey) != 0:
			err1Mex += 2*tab + 'mic flag must be 0\n'

		#Ack
		if getAckFlag(p1eapolKey) != 1:
			err1Mex += 2*tab + 'ack flag must be 1\n'

		#K
		if getPairwiseFlag(p1eapolKey) != 1:
			err1Mex += 2*tab + 'pairwise flag must be 1\n'

		#SM  (saltato)
		#keySRC
		if p1eapolKey.WPAKeyRSC != '\x00'*8:
			err1Mex += 2*tab + 'WPAKeyRSC field must be 0\n'

		#ANonce
		if p1eapolKey.Nonce == '\x00'*32:
			err1Mex += 2*tab + 'Nonce field can\'t be null\n'

		#MIC
		if p1eapolKey.WPAKeyMIC != '\x00'*16:
			err1Mex += 2*tab + 'WPAKeyMIC field must be 0\n'

		#Data
		if p1eapolKey.WPAKey != None:
			err1Mex += 2*tab + 'WPAKey field must be None\n'

		#Install
		if getInstallFlag(p1eapolKey) != 0:
			err1Mex += 2*tab + 'install flag must be 0\n'	

		#Ritorna la stringa di errori
		return err1Mex



	def secondPacketErrors(self):
		'''
		Ritorna un messaggio contenete le anomalie che ha il secondo pacchetto rispetto alle specifiche
		'''
		p2eapolKey = getEapolKeyPart(self.packet_2)
		err2Mex = ''	
		#Controlli
		#Bit secure
		if getSecureFlag(p2eapolKey) != 0:
			err2Mex += 2*tab + 'secure flag must be 0\n'

		#MIC_flagscapy 
		if getMicFlag(p2eapolKey) != 1:
			err2Mex += 2*tab + 'mic flag must be set\n'

		#Ack
		if getAckFlag(p2eapolKey) != 0:
			err2Mex += 2*tab + 'ack flag must be 0\n'

		#K
		if getPairwiseFlag(p2eapolKey) != 1:
			err2Mex += 2*tab + 'pairwise flag must be 1\n'

		#SM  (saltato)
		#keySRC
		if p2eapolKey.WPAKeyRSC != '\x00'*8:
			err2Mex += 2*tab + 'WPAKeyRSC field must be 0\n'

		#ANonce
		if p2eapolKey.Nonce == '\x00'*32:
			err2Mex += 2*tab + 'Nonce field can\'t be null\n'

		#MIC
		if p2eapolKey.WPAKeyMIC == '\x00'*16:
			err2Mex += 2*tab + 'WPAKeyMIC field can\'t be null\n'

		#Data
		if p2eapolKey.WPAKey == None:
			err2Mex += 2*tab + 'WPAKey field can\'t be null\n'

		#Install
		if getInstallFlag(p2eapolKey) != 0:
			err2Mex += 2*tab + 'install flag must be 0\n'	

		#Ritorna la stringa di errori	
		return err2Mex
	
	
	def thirdPacketErrors(self):
		'''
		Ritorna un messaggio contenete le anomalie che ha il terzo pacchetto rispetto alle specifiche
		'''
		p3eapolKey = getEapolKeyPart(self.packet_3)
		err3Mex = ''	
		#Controlli
		#Bit secure
		if getSecureFlag(p3eapolKey) != 1:
			err3Mex += 2*tab + 'secure flag must be set\n'

		#MIC_flagscapy 
		if getMicFlag(p3eapolKey) != 1:
			err3Mex += 2*tab + 'mic flag must be set\n'

		#Ack
		if getAckFlag(p3eapolKey) != 1:
			err3Mex += 2*tab + 'ack flag must be set\n'

		#K
		if getPairwiseFlag(p3eapolKey) != 1:
			err3Mex += 2*tab + 'pairwise flag must be set\n'

		#SM  (saltato)
		#keySRC
		if p3eapolKey.WPAKeyRSC == '\x00'*8:
			err3Mex += 2*tab + 'WPAKeyRSC field can\'t be 0\n'

		#ANonce
		if p3eapolKey.Nonce == '\x00'*32:
			err3Mex += 2*tab + 'Nonce field can\'t be null\n'

		#MIC
		if p3eapolKey.WPAKeyMIC == '\x00'*16:
			err3Mex += 2*tab + 'WPAKeyMIC field can\'t be null\n'

		#Data
		if p3eapolKey.WPAKey == None:
			err3Mex += 2*tab + 'WPAKey field can\'t be null\n'

		#Install
		if getInstallFlag(p3eapolKey) != 1:
			err3Mex += 2*tab + 'install flag must be set\n'	

		#Ritorna la stringa di errori
		return err3Mex
	
	
	def fourthPacketErrors(self):
		'''
		Ritorna un messaggio contenete le anomalie che ha il quarto pacchetto rispetto alle specifiche
		'''
		p4eapolKey = getEapolKeyPart(self.packet_4)
		err4Mex = ''
		#Controlli
		#Bit secure
		if getSecureFlag(p4eapolKey) != 1:
			err4Mex += 2*tab + 'secure flag must be set\n'

		#MIC_flagscapy 
		if getMicFlag(p4eapolKey) != 1:
			err4Mex += 2*tab + 'mic flag must be set\n'

		#Ack
		if getAckFlag(p4eapolKey) != 0:
			err4Mex += 2*tab + 'ack flag must be 0\n'

		#K
		if getPairwiseFlag(p4eapolKey) != 1:
			err4Mex += 2*tab + 'pairwise flag must be set\n'

		#SM  (saltato)
		#keySRC
		if p4eapolKey.WPAKeyRSC != '\x00'*8:
			err4Mex += 2*tab + 'WPAKeyRSC field must be 0\n'

		#ANonce
		if p4eapolKey.Nonce != '\x00'*32:
			err4Mex += 2*tab + 'Nonce field must be null\n'

		#MIC
		if p4eapolKey.WPAKeyMIC == '\x00'*16:
			err4Mex += 2*tab + 'WPAKeyMIC field can\'t be null\n'

		#Data
		if p4eapolKey.WPAKey != None:
			err4Mex += 2*tab + 'WPAKey field must be null\n'

		#Install
		if getInstallFlag(p4eapolKey) != 0:
			err4Mex += 2*tab + 'install flag must be 0\n'	

		#Ritorna la stringa di errori
		return err4Mex
	

	
	
		
		
		
	
