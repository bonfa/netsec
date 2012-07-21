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
	#tsc = struct.pack('6B',tsc5,tsc4,tsc3,tsc2,tsc1,tsc0)
	return tsc




class TkipDecryptor():
	'''
	Questa classe riceve in ingresso il pacchetto critpato e le chiavi per effettuare la decryption.
	Usando le chiavi decripta il pacchetto e ne controlla il MIC
	packet = pacchetto scapy (Dot11Wep)
	'''
	def __init__(self,packet,temporalKey,micKey):
		self.packet = packet
		self.tsc = getTSCfromPacket(packet)

		self.tk = temporalKey[0:16]
		self.fromAuthToSupplMichaelKey = temporalKey[16:24]
		self.fromSupplToAuthMichaelKey = temporalKey[24:32]
		
		self.ta = packet.addr2
		self.micKey = micKey
	


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
			
	

	def decryptPayload(self):
		'''
		Ritorna il pacchetto decriptato con la chiave
		Il metodo funziona solo con msdu che non vengono frammentate

		@TODO: introdurre la correzione per msdu che vengono frammentate in mpdu
		'''
		# Creo la mixing function
		mixingFunction = TKIPmixingFunction(self.tk,self.ta,self.tsc)
		
		# Calcolo il wep seed (tupla)
		wepSeed = mixingFunction.getWepSeed()
		
		# Non controllo il numero del pacchetto

		# L'mpdu è il pacchetto meno i primi 8 byte --> li tolgo alla prossima istruzione
		tkipMpduStr = str(self.packet[Dot11WEP])

		# I primi 8 byte sono i vari campi del "tkip"
		mpdu = struct.unpack('72B',tkipMpduStr[8:])
							
		# Creo il wep decryptor
		decryptor = WepDecryption(wepSeed[:3],wepSeed[3:],mpdu)

		# Estraggo il plainText	
		plainText = decryptor.getPlaintextAndIcv()
	

		# Controllo il MIC
		if self.checkMic():
			# ritorno il plaintext
			return plainText
		else:
			#errore MIC
			raise TKIPError('checkMic()','MIC does not match')
		

	

	def getDecryptedPacket(self):
		'''
		Prendo il payload decriptato, lo appendo all'header e ritorno il pacchetto completo
		'''		
		decriptedPayload = self.decryptPayload()

		
		decryptedPacket = self.packet
		decryptedPacket.wepdata = decriptedPayload

		return decryptedPacket





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


	
