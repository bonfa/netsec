#/usr/bin/python
# -*- coding: utf-8 -*-

'''
Effettua le due operazioni di encryption e decryption del tkip
'''

from scapy.all import *
import sys
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src/crypto')
from tkip_functions import TKIPmixingFunction
from rc4 import arcFour
import struct
import binascii


def getTSCfromPacket(packet):
	'''
	Riceve in ingresso un pacchetto e ritorna il campo TSC
	'''
	#prendo i campi del pacchetto WEP che mi interessano (iv e wepdata)
	iv = packet.iv
	data = packet.wepdata
	#estraggo i campi di tsc
	tsc1 = int(binascii.hexlify(iv[0]),16)
	tsc0 =  int(binascii.hexlify(iv[2]),16)
	tsc2 =  int(binascii.hexlify(data[0]),16)
	tsc3 =  int(binascii.hexlify(data[1]),16)
	tsc4 =  int(binascii.hexlify(data[2]),16)
	tsc5 =  int(binascii.hexlify(data[3]),16)
	
	#creo il tsc --> lo creo come lista
	tsc = struct.pack('6B',tsc0,tsc1,tsc2,tsc3,tsc4,tsc5)
	return tsc




class TkipDecryptor():
	'''
	Questa classe riceve in ingresso il pacchetto critpato e le chiavi per effettuare la decryption.
	Usando le chiavi decripta il pacchetto e ne contraolla il MIC
	'''
	def __init__(self,packet,temporalKey,micKey):
		self.packet = packet
		self.tsc = getTSCfromPacket(packet)
		print (len(binascii.hexlify(temporalKey).decode('hex')))
		self.tk = struct.unpack('8B',binascii.hexlify(temporalKey).decode('hex'))
		self.ta = packet.addr2
		self.micKey = micKey
	


	def getMic(self):
		'''
		Ritorna il MIC del pacchetto
		'''
				

		

	
	def getDecryptedPacket(self):
		'''
		Ritorna il pacchetto decriptato con la chiave
		Il metodo funziona solo con msdu che non vengono frammentata
		@TODO: introdurre la correzione per msdu che vengono frammentate in mpdu
		'''
		#creo la mixing function
		mixingFunction = TKIPmixingFunction(self.tk,self.ta,self.tsc)
		
		#calcolo il wep seed
		wepSeed = mixingFunction.getWepSeed()
		
		# Non controllo il numero del pacchetto
		# l'mpdu è il pacchetto
		print str(packet)
		mpdu = self.packet[Dot11WEP]
		
		# Creo il cipher		
		cipher = arcFour(self.tk)
		# imposto l'input
		cipher.setInput(mpdu)
		
		# effettuo la cifratura
		plaintext = cipher.getInput()

		# manca il controllo del mic
		return plaintext


	


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























	
