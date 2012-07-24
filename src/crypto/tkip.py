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
from tkip_mic_utility import TkipMicGenerator


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
		self.temporalKey = temporalKey
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
		return plaintext


	def getCipherText(self):
		'''
		Estrae dal pacchetto scapy la stringa del cipher_text e la ritorna
		'''
		icvStr = struct.pack('>I',self.packet.icv)
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
		i1,i2,i3,i4,i5,i6 = macIntegerList
		macAddrStr = struct.pack('6B',i1,i2,i3,i4,i5,i6)
		return macAddrStr
	


	def getIV(self):
		'''
		Estrae dal pacchetto scapy la stringa dell'IV e la ritorna
		'''
		# IV + extendedIV
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
	def __init__(self,ciphertext,srcAddr,iv,temporalKey,micKey,dstAddr,priorityField):
		self.da = dstAddr
		self.priority = priorityField
		reservedTuple = (0x00,0x00)*12
		self.reserved = struct.pack('24B',*reservedTuple)
		self.ta = srcAddr
		self.tsc = getTSC(iv)
		self.iv = iv
		self.tk = temporalKey
		self.micKey = micKey
		self.ciphertext = ciphertext



	def decryptPayload(self):
		#printTKIP_parameters(self.tk,self.iv,self.ta,self.ciphertext)
		# Creo la mixing function
		mixingFunction = TKIPmixingFunction(self.tk,self.ta,self.tsc)
		
		# Calcolo il wep seed (tupla)
		wepSeed = mixingFunction.getWepSeed()
		#printWepSeed(wepSeed)		
	
		# Passo da stringa a tupla
		lunghezza = len(self.ciphertext)
		stringFormat = str(lunghezza)+'B'
		cipher_tuple = struct.unpack(stringFormat,self.ciphertext)

		ivTuple = ()

		# Decripto la tupla
		decryptor = WepDecryption(ivTuple,wepSeed,cipher_tuple)	
			
		# Estraggo il plaintext --> tupla
		plaintextAndIcv = decryptor.getPlaintextAndIcv()

		# Controllo il MIC
		if self.checkMic(plaintextAndIcv[:-4]):
			# ritorno il plaintext
			return plaintextAndIcv
		else:
			#errore MIC
			raise TKIPError('checkMic()','MIC does not match')
	

	
	def checkMic(self,plaintextAndMic):
		'''
		Controllo che il mic calcolato sia uguale al mic generato
		Ho il plaintextAndMic --> tupla
		Devo passare a stringa
		'''
		#il mic sono gli ultimi 8 byte del pacchetto ricevuto
		micReceived = plaintextAndMic[-8:]
		incompletePlaintext = plaintextAndMic[:-8]
		micProcessed = self.getMic(incompletePlaintext)

		print len(micProcessed)
		print 'RECEIVED = ' + str(micReceived)
		print 'PROCESSED = ' + str(struct.unpack('8B',micProcessed))
		return (micReceived == micProcessed)



	def getMic(self,incompletePlaintext):
		'''
		Ritorna il MIC del pacchetto
		Ho il plaintext incompleto --> tupla
		'''
		# trasformo la tupla in stringa
		formatStr = str(len(incompletePlaintext))+'B'
		incompletePlaintextStr = struct.pack(formatStr,*incompletePlaintext)
		#preparo il pacchetto per il calcolo del MIC
		plaintextStrForMic = self.getPlaintextForMic(incompletePlaintextStr)
		#ritorna il mic
		micGen = TkipMicGenerator(plaintextStrForMic,self.micKey)
		print 'PLAINTEXT_FOR_MIC = ' + plaintextStrForMic
		return micGen.getMic()



	def getPlaintextForMic(self,incompletePlaintext):
		'''
		Prende il pacchetto e gli appende destination address, source address, priority field e reserved bytes
		incompletePlaintext --> tupla
		return --> tupla
		'''
		# Concateno i campi in ordine
		print 'SA = ' + str(struct.unpack('6B',self.da))
		print 'DA = ' + str(struct.unpack('6B',self.ta))
		print 'PRIO = ' + str(struct.unpack('1B',self.priority)[0])
		
		completePlaintext = self.da + self.ta + self.priority + self.reserved + incompletePlaintext

		#debug
		formatStr = str(len(incompletePlaintext))+'B'
		print 'INC = ' + str(struct.unpack(formatStr,incompletePlaintext))
		formatStr = str(len(completePlaintext))+'B'
		print 'COMPL = ' + str(struct.unpack(formatStr,completePlaintext))

		return completePlaintext



def printTKIP_parameters(tk,iv,sa,ciphertext):
	print 'SOURCE ADDRESS  = ' + str(struct.unpack('6B',sa[:]))
	print 'IV  = ' + str(struct.unpack('8B',iv[:]))
	print 'TK  = ' + str(struct.unpack('16B',(tk[:16])[:]))
	print '\nCIPHERTEXT = ' + str(struct.unpack('72B',ciphertext[:]))


def printWepSeed(wepSeed):
	wepHex = []
	for i in range(len(wepSeed)):
		wepHex.append(int(wepSeed[i]))
	print 'WEP SEED = ' + str(wepHex)

