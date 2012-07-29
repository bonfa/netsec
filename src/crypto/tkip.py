#/usr/bin/python
# -*- coding: utf-8 -*-

'''
Effettua le due operazioni di encryption e decryption del tkip
'''

from scapy.all import *
import sys
sys.path.append('../crypto')
sys.path.append('../utilities')
from tkip_functions import TKIPmixingFunction
from exception import TKIPError,FlagException
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
	def __init__(self,packet,temporalKey,micKey,fcsPresent=False):
		self.packet = packet
		self.temporalKey = temporalKey
		self.micKey = micKey
		self.fcsPresent = fcsPresent

			

	def getDecryptedPacket(self):	
		'''
		Ritorna un pacchetto radiotap + 802.11 + mpdu decriptata
		'''
		#estraggo i valori dal pacchetto
		ciphertext = self.getCipherText()
		srcAddr = self.getSrcAddress()
		iv8 = self.getIV()
		temporalKey = self.temporalKey
		micKey = self.micKey
		dstAddr = self.getDstAddress()
		priorityField = self.getPriorityField()
		transmAddr = self.getTransmissionAddress()
		#decripto
		decryptor = TKIP_Decryptor_Low(ciphertext,srcAddr,dstAddr,transmAddr,iv8,temporalKey,micKey,priorityField)
		plaintextAndMic = decryptor.decryptPayload()		
		#prendo il plaintext --> tupla
		plaintextTuple = plaintextAndMic[:-8]

		#creo un pacchetto radiotap + 802.11 + payload decriptato
		newPack = self.appendPayload(plaintextTuple)
		return newPack



	def appendPayload(self,plaintext):
		'''
		prende il pacchetto 802.11 e crea un pacchetto EtherII con payload il plaintext privato dell'header LLC
		plaintext --> tupla
		'''
		if plaintext[0] != 170:
			raise TKIPError('Preamble != 0xAA-AA-03','Packet kind decryption not managed')
		else:
			ethField = Ether()
			ethField.dst = self.getSrcAddress()
			ethField.src = self.getDstAddress()
			ethField.type = plaintext[6]*16*16+plaintext[7]
			pl = plaintext[8:]
			ethFieldStr = str(ethField)
			ethField = Ether(ethFieldStr+struct.pack(str(len(pl))+'B',*pl))
		return ethField



	def getCipherText(self):
		'''
		Estrae dal pacchetto scapy la stringa del cipher_text e la ritorna
		'''
		if (self.fcsPresent):
			return self.packet.wepdata[4:]
		else:
			icvStr = struct.pack('>I',self.packet.icv)
			return self.packet.wepdata[4:] + icvStr
	

	
	def getSrcAddress(self):
		'''
		Estrae dal pacchetto scapy la stringa del src_address e la ritorna
		'''
		toDsFromDs = self.packet.FCfield & 0x3
		if toDsFromDs==0 or toDsFromDs==1:
			macAddrScapy = str(self.packet.addr2)
		elif toDsFromDs==2:
			macAddrScapy = str(self.packet.addr3)
		elif toDsFromDs==3:
			macAddrScapy = str(self.packet.addr4)
		else:
			raise TKIPError('toDsFromDs not in (0,1,2,3)','Error in flags')
		return self.getAddrStr(macAddrScapy)
	


	def getTransmissionAddress(self):
		'''
		Estrae dal pacchetto scapy la stringa del src_address e la ritorna
		'''
		macAddrScapy = str(self.packet.addr2)
		return self.getAddrStr(macAddrScapy)



	def getDstAddress(self):
		'''
		Estrae dal pacchetto scapy la stringa del dst_address e la ritorna
		'''
		toDsFromDs = self.packet.FCfield & 0x3
		if toDsFromDs==0 or toDsFromDs==2:
			macAddrScapy = str(self.packet.addr1)
		elif toDsFromDs==1 or toDsFromDs==3:
			macAddrScapy = str(self.packet.addr3)
		else:
			raise TKIPError('toDsFromDs not in (0,1,2,3)','Error in flags')
		return self.getAddrStr(macAddrScapy)



	def getAddrStr(self,macAddrScapy):
		'''
		Riceve in input un indirizzo scapy e torna la stringa corrispondente
		'''
		macAddrTuple = (macAddrScapy).split(':')
		macIntegerList = []
		for i in range(len(macAddrTuple)):
			macIntegerList.append(int(macAddrTuple[i],16))
		i1,i2,i3,i4,i5,i6 = macIntegerList
		macAddrStr = struct.pack('6B',i1,i2,i3,i4,i5,i6)
		return macAddrStr



	def getPriorityField(self):
		'''
		Ritorna il priority field del pacchetto
		@TODO: tornare un valore diverso nel caso di QoS non nullo
		'''
		return chr(0)


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
	def __init__(self,ciphertext,srcAddr,dstAddr,trasmAddr,iv,temporalKey,micKey,priorityField):
		self.ciphertext = ciphertext
		self.sa = srcAddr
		self.da = dstAddr
		self.ta = trasmAddr
		self.iv = iv
		self.tk = temporalKey
		self.micKey = micKey		
		self.priority = priorityField
		self.reserved = 3*chr(0)
		self.tsc = getTSC(iv)
		


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
		
		#print 'PLAINTEXT = ' + str(plaintextAndIcv)
	
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
		micReceivedTuple = plaintextAndMic[-8:]
		msduNoMic = plaintextAndMic[:-8]
		micProcessed = self.getMic(msduNoMic)

		#print len(micProcessed)
		#print '   RECEIVED = ' + str(micReceivedTuple)
		#print '   PROCESSED = ' + str(struct.unpack('8B',micProcessed))
		return (micReceivedTuple == struct.unpack('8B',micProcessed))



	def getMic(self,msduNoMic):
		'''
		Ritorna il MIC del pacchetto
		Ho il plaintext incompleto --> tupla
		'''
		# trasformo la tupla in stringa
		formatStr = str(len(msduNoMic))+'B'
		msduNoMicStr = struct.pack(formatStr,*msduNoMic)
		#preparo il pacchetto per il calcolo del MIC
		paddedMSDU = self.getPaddedMSDU(msduNoMicStr)
		#ritorna il mic
		
		#print 'LUNGH = ' + str(len(paddedMSDU))
		formatStr = str(len(paddedMSDU))+'B'
		paddedMSDUTuple = struct.unpack(formatStr,paddedMSDU)	
		#print 'PLAINTEXT_FOR_MIC = ' + str(paddedMSDUTuple)
		micGen = TkipMicGenerator(paddedMSDU,self.micKey)
		return micGen.getMic()



	def getPaddedMSDU(self,msdu):
		'''
		Prende il pacchetto e gli appende destination address, source address, priority field e reserved bytes
		msdu --> tupla
		return --> tupla
		'''
		# Concateno i campi in ordine
		#print 'SA = ' + str(struct.unpack('6B',self.sa))
		#print 'DA = ' + str(struct.unpack('6B',self.da))
		#print 'TA = ' + str(struct.unpack('6B',self.ta))
		#print 'PRIO = ' + str(struct.unpack('1B',self.priority)[0])
		
		if (self.priority == None):
			paddedMSDU = self.da + self.sa + msdu
		else:
			paddedMSDU = self.da + self.sa + self.priority + self.reserved + msdu

		#debug
		formatStr = str(len(msdu))+'B'
		#print 'INC = ' + str(struct.unpack(formatStr,msdu))
		formatStr = str(len(paddedMSDU))+'B'
		#print 'COMPL = ' + str(struct.unpack(formatStr,paddedMSDU))

		return paddedMSDU



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

