#/usr/bin/python
# -*- coding: utf-8 -*-

'''
Effettua le due operazioni di encryption e decryption del tkip
'''

from scapy.all import *
import sys
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src/crypto')
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src/utilities')
from tkip_functions import TKIPmixingFunction
from exception import TKIPError
import struct
import binascii
from wep import WepDecryption



def getTSC(iv8String):
	'''
	Riceve in ingresso un iv a 8 bit e ritorna il campo TSC
	'''
	iv8 = struct.unpack('8B',iv8String)
	tsc1 = iv8[0]
	tsc0 = iv8[2]
	tsc5 = iv8[7]
	tsc4 = iv8[6]
	tsc3 = iv8[5]
	tsc2 = iv8[4]	
	tsc = struct.pack('6B',tsc0,tsc1,tsc2,tsc3,tsc4,tsc5)
	return tsc



class TKIP_Decryptor_Low():
	'''
	srcAddr,iv,temporalKey,micKey sono stringhe
	'''		
	def __init__(self,ciphertext,srcAddr,iv,temporalKey,micKey):
		self.ta = srcAddr
		self.tsc = getTSC(iv)
		self.iv = iv
		self.tk = temporalKey
		self.micKey = micKey
		self.ciphertext = ciphertext



	def decryptPayload(self):
		# Creo la mixing function
		mixingFunction = TKIPmixingFunction(self.tk,self.ta,self.tsc)
		
		# Calcolo il wep seed (tupla)
		wepSeed = mixingFunction.getWepSeed()

		# wepseed è giusto
		print 'WEP SEED'			
		wepHex = []
		for i in range(len(wepSeed)):
			wepHex.append(int(wepSeed[i]))
		print wepHex
	
		# Passo da stringa a tupla
		lunghezza = len(self.ciphertext)
		stringa = str(lunghezza)+'B'
		cipher_tuple = struct.unpack(stringa,self.ciphertext)

		ivTuple = ()

		# Decripto la tupla
		decryptor = WepDecryption(ivTuple,wepSeed,cipher_tuple)	
			
		# Estraggo il plainText	
		plainText = decryptor.getPlaintextAndIcv()

		# Controllo il MIC
		if self.checkMic():
			# ritorno il plaintext
			return plainText
		else:
			#errore MIC
			raise TKIPError('checkMic()','MIC does not match')
	

	
	def checkMic(self):
		'''
		Controllo che il mic calcolato sia uguale al mic generato
		@TODO: implementare il metodo
		'''
		return True
	
