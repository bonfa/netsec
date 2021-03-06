#/usr/bin/python
# -*- coding: utf-8 -*-
'''
Questo modulo implementa i metodi di crittografia usati dal 4 way handshake
'''
import sys
sys.path.append('../common_utility')
sys.path.append('../packetStruct')
sys.path.append('../utilities')
sys.path.append('../crypto')
import base_crypto_utility
from exception import pmkTooShortException,MacNotSupportedException,InputError
import hmac
import hashlib
from packet_subfields import getDescriptorFlag,setKeyMicField,getEapolPayload,printPacket
import binascii


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



class passphraseToPSKMap:
	'''
	Classe passphraseToPSKMap

	Genera la psk a partire dall'ssid della rete e dalla passphrase di accesso per quella rete
	'''
	
	def __init__(self,passphrase,ssid):
		'''
		Imposta i valori necessari alla generazione della psk
		'''
		if len(passphrase)< 8 or len(passphrase) > 63:
			raise InputError(('len(passphrase)< 8 or len(passphrase) > 63','Error in passphrase length'))
		if len(ssid)<0 or len(ssid)>32:
			raise InputError(('len(ssid)<0 or len(ssid)>32','Error in ssid length'))
		self.passphrase = passphrase
		self.ssid = ssid
	

	def getPsk(self):
		'''
		genera ritorna la psk generata a partire dalla passphrase
		'''
		psk = base_crypto_utility.pbkdf2(self.passphrase,self.ssid,4096)
		return psk



class cryptoManager:
	'''
	Classe cryptoManager

	Contiene i metodi di crittografia chiamati durante le operazioni del 4 way handshake
	@TODO: eliminare il packetObject e sostituire con le funzionalità di scapy
	'''
	def __init__(self,packet,packetObject,kek,kck):
		self.kek = kek
		self.kck = kck
		self.packet = packet
		self.packetObject = packetObject
	

	
	def getMicString(self):
		'''
		Ritorna la stringa che rappresenta il MIC del pacchetto eapol
		'''
		micStr = self.getMicHexString()
		return binascii.unhexlify(micStr)
	


	def getMicHexString(self):
		'''
		Ritorna il MIC del pacchetto eapol
		La stringa contiene dei caratteri esadecimali (esempio AA BB CC DD EE)
		'''
		# controllo che il descriptor sia corretto
		eapolpacket = self.packetObject.payload
		if eapolpacket.payload.key_information.key_descriptor_version == 1:
			# preparo il pacchetto con il campo MIC nullo
			packetWithNullMICFieldTuple = self.clearKeyMicField()
			# print (packetWithNullMICFieldTuple)
			packetWithNullMICField = (packetWithNullMICFieldTuple)
			# tolgo l'header ethernet
			eapolPacketWithNullMIC = self.getEapolPayload(packetWithNullMICField)		
			# creo l'oggetto che crea il digest
			digestMaker = hmac.new(self.kck,eapolPacketWithNullMIC,hashlib.md5)
			# ritorno il digest			
			return digestMaker.hexdigest()			
		else:
			raise MacNotSupportedException('eapolpacket.payload.descriptor_type == 1','Not supported mic type')



	def clearKeyMicField(self):
		'''
		Prende pacchetto e ne annulla il campo key mic
		'''
		packetWithNullMICField = self.packet[0:95]		
		packetWithNullMICField = packetWithNullMICField + (chr(0x00)+chr(0x00)+chr(0x00)+chr(0x00)+chr(0x00)+chr(0x00)+chr(0x00)+chr(0x00))
		packetWithNullMICField = packetWithNullMICField + (chr(0x00)+chr(0x00)+chr(0x00)+chr(0x00)+chr(0x00)+chr(0x00)+chr(0x00)+chr(0x00))
		packetWithNullMICField = packetWithNullMICField + self.packet[95+16:]
		return packetWithNullMICField
		


	@classmethod
	def getEapolPayload(self,packet):
		'''
		Dal pacchetto eapol toglie l'header ethernet e ritorna solo il pacchetto eapol		
		'''
		return packet[14:]



		
