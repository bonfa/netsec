#/usr/bin/python
# -*- coding: utf-8 -*-

'''
Effettua le due operazioni di encryption e decryption del tkip
'''

from scapy.all import *
import sys
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src/crypto')
from tkip_functions import TKIPmixingFunction



def getTSCfromPacket(packet):
	'''
	Riceve in ingresso un pacchetto e ritorna il campo TSC
	'''
	#prendo i campi del pacchetto WEP che mi interessano (iv e wepdata)
	iv = packet.iv
	data = packet.wepdata
	#estraggo i campi di tsc
	tsc1 = iv[0:2]
	tsc0 = iv[4:6]
	tsc2 = data[0:2]
	tsc3 = data[2:4]
	tsc4 = data[4:6]
	tsc5 = data[6:8]
	#creo il tsc --> lo creo come lista
	tsc = [tsc0,tsc1,tsc2,tsc3,tsc4,tsc5]
	return tsc




class TkipDecryptor():
	'''
	Questa classe riceve in ingresso il pacchetto critpato e le chiavi per effettuare la decryption.
	Usando le chiavi decripta il pacchetto e ne contraolla il MIC
	'''
	def __init__(self,packet,temporalKey,micKey):
		self.tsc = getTSCfromPacket(criptedPacket)
		self.tk = temporalKey	
		self.ta = packet.addr2
		self.micKey = micKey
	


	def getMic(self):
		'''
		Ritorna il MIC del pacchetto
		'''
				

		

	
	def getDecryptedPacket(self):
		'''
		Ritorna il pacchetto decriptato con la chiave
		'''
		#creo la mixing function
		mixingFunction = TKIPmixingFunction(self.tk,self.ta,self.tsc)
		
		#wepSeed
		
		
		


class TkipEncryptor():
	'''
	Questa classe riceve in ingresso il pacchetto in chiaro e le chiavi per effettuare l'encryption.
	Usando le chiavi fa il MIC del pacchetto e lo cripta
	@TODO: completare le funzioni
	'''
	
	def __init__(self,packet,temporalKey,micKey):
		self.tsc = getTSCfromPacket(criptedPacket)
		self.tk = temporalKey	
		self.ta = packet.addr2
		self.micKey = micKey
	


	def getMic(self):
		'''
		Ritorna il MIC del pacchetto
		'''

	

	def getEncrypted(self):
		'''
		Ritorna il pacchetto criptato con la chiave
		'''























	
