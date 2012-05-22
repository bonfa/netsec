#/usr/bin/python
# -*- coding: utf-8 -*-
'''
Questo modulo implementa i metodi di crittografia usati dal 4 way handshake
'''
import sys
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src/common_utility')
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src/packetStruct')
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src')
import base_crypto_utility
from exception import pmkTooShortException,MacNotSupportedException
from hashlib import md5
import hmac



class keyGenerator:
	'''
	Classe keyGenerator

	Crea la chiave e la splitta nelle chiavi di sessione 
	'''
	
	def __init__(self,pmk,mex,AA,SPA,ANonce,SNonce):
		'''
		Imposta i dati necessari al keyGenerator:
		PMK è la chiave. Se la pmk è più lunga di 256 bit, viene troncata.
		I valori AA,SPA,ANonce,SNonce sono i campi fondamentali che costituiranno il messaggio di cui calcolare l'hash
		Length è la lunghezza del risultato della prf
		'''
		if len(pmk) > 32:
			self.pmk = self.curtailPmk(pmk,0,32)
		elif len(pmk) < 32:
			raise pmkTooShortException('len(pmk) < 32','pmk is too short')
		else:
			self.pmk = pmk
		self.mex = mex
		self.AA = AA
		self.SPA = SPA
		self.ANonce = ANonce
		self.SNonce = SNonce
		


	def prf(self):
		'''
		effettua la prf 
		'''
		(minAddress,maxAddress,minNonce,maxNonce) = self.orderPadding()
		variablePart = minAddress + maxAddress + minNonce + maxNonce
		return base_crypto_utility.prf_512(self.pmk,self.mex,variablePart)


	def getKeys(self):
		'''
		ottiene la prf, da essa estrae le chiavi KEK,KCK,TK,authenticatorMicKey,supplicantMicKey e ritorna una tupla che contiene le tre chiavi nel seguente ordine [KEK,KCK,TK,authenticatorMicKey,supplicantMicKey]
		'''
		prf = self.prf()
		kck = base_crypto_utility.left(prf,0,16)
		kek = base_crypto_utility.left(prf,16,16)
		tk = base_crypto_utility.left(prf,32,32)
		authenticatorMicKey = base_crypto_utility.left(prf,48,8)
		supplicantMicKey = base_crypto_utility.left(prf,56,8)
		return [kck,kek,tk,authenticatorMicKey,supplicantMicKey]
		

	def orderPadding(self):
		'''
		Ritorna la tupla ordinata che rappresenta il messaggio
		'''
		minAddress = min(self.AA,self.SPA)
		maxAddress = max(self.AA,self.SPA)
		minNonce = min(self.ANonce,self.SNonce)
		maxNonce = max(self.ANonce,self.SNonce)
		return (minAddress,maxAddress,minNonce,maxNonce)	


	@classmethod
	def curtailPmk(cls,pmk,start,end):
		'''
		Se la pmk è troppo lunga, la seleziona tra start e start+end
		'''
		return base_crypto_utility.left(pmk,start,end)





class cryptoManager:
	'''
	Classe cryptoManager

	Contiene i metodi di crittografia chiamati durante le operazioni del 4 way handshake
	'''
	def __init__(self,packet,packetObject,kek,kck):
		self.kek = kek
		self.kck = kck
		self.packet = packet
		self.packetObject = packetObject
	

	def getMic(self):
		'''
		Ritorna il MIC del pacchetto eapol
		'''
		#prendo il pacchetto header
		eapolpacket = self.packetObject.payload
		if eapolpacket.payload.key_information.key_descriptor_version == 1:
			# preparo il pacchetto con il campo MIC nullo
			packetWithNullMICField = self.packet[0:95]
			packetWithNullMICField = packetWithNullMICField + (chr(0x00),chr(0x00),chr(0x00),chr(0x00),chr(0x00),chr(0x00),chr(0x00),chr(0x00))
			packetWithNullMICField = packetWithNullMICField + (chr(0x00),chr(0x00),chr(0x00),chr(0x00),chr(0x00),chr(0x00),chr(0x00),chr(0x00))
			packetWithNullMICField = packetWithNullMICField + self.packet[95+16:]
			# calcolo il digest e lo ritorno
			digestMaker = hmac.new(self.kck)
			digestMaker.update(str(packetWithNullMICField))
			return digestMaker.hexdigest()
			
		else:
			print ord(eapolpacket.payload.EapolKeyInformationField.key_descriptor_version)
			raise MacNotSupportedException('eapolpacket.payload.descriptor_type == 1','Not supported mic type')


