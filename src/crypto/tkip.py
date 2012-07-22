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



class TkipDecryptor():
	'''
	Classe di alto livello che viene chiamata dal main
	Prepara l'input nel formato giusto e chiama TKIP_Decryptor_Low con il nuovo input
	@TODO: inserire controlli sulla lunghezza dell'input
	packet è un pacchetto scapy
	temporalKey, micKey sono stringhe		
	'''
	def __init__(self,packet,temporalKey,micKey):
		self.packet = packet
		self.temporalKey = temporalKey[:16]
		self.micKey = micKey

			

	def getDecryptedPacket(self):	
		'''
		Ritorna l'mpdu decriptata
		'''
		#estraggo i valori dal pacchetto
		ciphertext = self.getCipherText()
		srcAddr = self.getSrcAddress()
		iv8 = self.getIV()
		temporalKey = self.temporalKey
		micKey = self.micKey
		#decripto
		decryptor = TKIP_Decryptor_Low(ciphertext,srcAddr,iv8,temporalKey,micKey)	
		plaintext = decryptor.decryptPayload()		
		## non so se devo appenderci qualcosa



	def getCipherText(self):
		'''
		Estrae dal pacchetto scapy la stringa del cipher_text e la ritorna
		'''
		icvStr = struct.pack('>I',self.packet.icv)
		#print a
		#print struct.unpack('>4B',a)
		return self.packet.wepdata[4:] + icvStr
	

	
	def getSrcAddress(self):
		'''
		Estrae dal pacchetto scapy la stringa del src_address e la ritorna
		'''
		macAddrScapy = str(self.packet.addr2)
		macAddrTuple = (macAddrScapy).split(':')
		macIntegerList = []
		for i in range(len(macAddrTuple)):
			macIntegerList.append(int(macAddrTuple[i],16))
		#print macIntegerList
		i1,i2,i3,i4,i5,i6 = macIntegerList
		macAddrStr = struct.pack('6B',i1,i2,i3,i4,i5,i6)
		#print ord(macAddrStr[0])
		return macAddrStr
	


	def getIV(self):
		'''
		Estrae dal pacchetto scapy la stringa dell'IV e la ritorna
		'''
		# IV + extendedIV
		#print struct.unpack('3B',self.packet.iv)
		print struct.pack('1B',self.packet.keyid)
		print (self.packet.wepdata[:4])
		return self.packet.iv + struct.pack('1B',self.packet.keyid) + self.packet.wepdata[:4]
		



class TKIP_Decryptor_Low():
	'''
	Classe che si interfaccia con la classe WEP
	Gli input di questa classe sono stringhe
	srcAddr,iv,temporalKey,micKey sono stringhe
	@TODO: inserire controlli sulla lunghezza dell'input
	iv --> 8 byte
	temporalKey --> 16B
	micKey --> 
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



	def getMic(self):
		'''
		Ritorna il MIC del pacchetto
		@TODO: implementare il metodo
		'''


	
