#/usr/bin/python
# -*- coding: utf-8 -*-

'''
Effettua le due operazioni di encryption e decryption del wep
'''

import binascii
import sys
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src/utilities')
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src/crypto')
from exception import WepError
from rc4 import arcFour
import struct


class WepDecryption():
	'''
	Effettua la decryption wep
	iv, key, ciphertext sono tuple

	@TODO: inserire i controlli sulla lunghezza della chiave (5 o 13 byte) dell'iv (3 byte) 
	'''
	def __init__(self,iv,key,ciphertext):
		if type(iv) != tuple:
			raise TypeError("iv type must be 'tuple'")
		if type(key) != tuple:
			raise TypeError("key type must be 'tuple'")
		if type(ciphertext) != tuple:
			raise TypeError("plaintext type must be 'tuple'")
		#concateno iv e key
		self.seed = iv + key
		self.ciphertext = ciphertext



	def getPlaintextAndIcv(self):
		'''
		Ritorna il plaintext + icv
		il plaintext è una tupla
		'''
		#definisco il cipher
		cipher = arcFour(self.seed)
		
		arc4Input = self.ciphertext
		
		# faccio lo xor tra il ciphertext e il keystream
		output = []
		for i in range(len(arc4Input)):
			keyStreamByte = cipher.getKeyStreamByte()	
			outputBlock = arc4Input[i] ^ keyStreamByte
			output.append(outputBlock)
		plaintextAndCrc = tuple(output)

		mex = plaintextAndCrc[:-4]
		icv = plaintextAndCrc[-4:]
		# calcolo l'icv del pacchetto e controllo che sia uguale all'icv reale
		icv_ok = self.checkICV(mex,icv)

		if icv_ok:
			return plaintextAndCrc
		else:
			raise WepError('icv_ok','ICV does not match');


	
	def checkICV(self,plaintext,icv_received):
		'''
		Controlla che l'ICV sia corretto
		plaintext è una tupla
		icv_received è una tupla
		'''
		icv_processed = crc32Tuple(plaintext)
		return (icv_received == icv_processed)



class WepEncryption():
	'''
	Effettua l'encryption wep
	iv, key, plaintext sono tuple
	
	@TODO: inserire i controlli sulla lunghezza della chiave (5 o 13 byte) dell'iv (3 byte) 
	'''
	def __init__(self,iv,key,plaintext):
		if type(iv) != tuple:
			raise TypeError("iv type must be 'tuple'")
		if type(key) != tuple:
			raise TypeError("key type must be 'tuple'")
		if type(plaintext) != tuple:
			raise TypeError("plaintext type must be 'tuple'")
		#concateno iv e key
		self.seed = iv + key
		self.plaintext = plaintext

	
	
	def getCiphertext(self):
		'''
		Ritorna il plaintext criptato con wep
		il ciphertext è una tupla
		'''		
		#definisco il cipher
		cipher = arcFour(self.seed)
		
		#calcolo il crc32 del plaintext --> tupla
		crc32  = crc32Tuple(self.plaintext)

		#appendo il crc32 al plaintext
		arc4Input = self.plaintext + crc32
		
		# faccio lo xor tra il risultato e il keystream
		output = []
		for i in range(len(arc4Input)):
			keyStreamByte = cipher.getKeyStreamByte()	
			outputBlock = arc4Input[i] ^ keyStreamByte
			output.append(outputBlock)
		return tuple(output)
		



def crc32Value(data):
	'''
	Ritorna il crc32 del data
	data è una tupla
	crc32 è un long
	'''
	dataString = tupleToString(data)
	return binascii.crc32(dataString)



def crc32Tuple(data):
	'''
	Ritorna il crc32 del data
	data è una tupla
	crc32 è una tupla
	'''
	crcValue = crc32Value(data)
	crcString = struct.pack('I',crcValue)
	crcTuple = struct.unpack('4B',crcString)
	return crcTuple



def tupleToString(aTuple):
	'''
	Riceve in ingresso una tupla di valori esadecimali e ritorna la stringa ottenuta convertendo ciascun valore decimale nel suo simbolo (carattere) corrispondente
	'''
	# Converto ciascun valore nel suo carattere corrispondente
	b = []
	for i in range(len(aTuple)):
		b.append(chr(aTuple[i]))
	# Faccio il join di tutti i caratteri
	c = ''.join(b)
	return c



