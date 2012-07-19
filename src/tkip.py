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

		self.tk = temporalKey[0:16]
		self.fromAuthToSupplMichaelKey = temporalKey[16:24]
		self.fromSupplToAuthMichaelKey = temporalKey[24:32]
		
		self.ta = packet.addr2
		self.micKey = micKey
	



	def getMic(self):
		'''
		Ritorna il MIC del pacchetto
		'''
			
	

	def decryptPayload(self):
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
		
		mpdu = struct.unpack('80B',str(self.packet[Dot11WEP]))
		
		# Creo il cipher		
		cipher = arcFour(struct.unpack('16B',self.tk))
		# imposto l'input
		cipher.setInput(mpdu)
		
		# effettuo la cifratura
		plaintextTuple = cipher.getOutput()

		# manca il controllo del mic
		
		# separo la tupla nei singoli valori
		p0,p1,p2,p3,p4,p5,p6,p7,p8,p9,p10,p11,p12,p13,p14,p15,p16,p17,p18,p19,p20,p21,p22,p23,p24,p25,p26,p27,p28,p29,p30,p31,p32,p33,p34,p35,p36,p37,p38,p39,p40,p41,p42,p43,p44,p45,p46,p47,p48,p49,p50,p51,p52,p53,p54,p55,p56,p57,p58,p59,p60,p61,p62,p63,p64,p65,p66,p67,p68,p69,p70,p71,p72,p73,p74,p75,p76,p77,p78,p79 = plaintextTuple

		# ritorno la stringa 
		plaintext = struct.pack('80B',p0,p1,p2,p3,p4,p5,p6,p7,p8,p9,p10,p11,p12,p13,p14,p15,p16,p17,p18,p19,p20,p21,p22,p23,p24,p25,p26,p27,p28,p29,p30,p31,p32,p33,p34,p35,p36,p37,p38,p39,p40,p41,p42,p43,p44,p45,p46,p47,p48,p49,p50,p51,p52,p53,p54,p55,p56,p57,p58,p59,p60,p61,p62,p63,p64,p65,p66,p67,p68,p69,p70,p71,p72,p73,p74,p75,p76,p77,p78,p79)
	
		# ritorno il plaintext
		return plaintext


	
	def getDecryptedPacket(self):
		'''
		Prendo il payload decriptato, lo appendo all'header e ritorno il pacchetto completo
		'''		
		decriptedPayload = self.decryptPayload()
		strPacket = str(self.packet[RadioTap])+str(self.packet[Dot11])+decriptedPayload
		return strPacket



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























	
