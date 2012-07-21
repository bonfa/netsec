#/usr/bin/python
# -*- coding: utf-8 -*-

'''
Effettua le due operazioni di encryption e decryption del wep
'''

import binascii
#from exception import WepError
import sys
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src/utilities')
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src/crypto')
from rc4 import arcFour
import struct


class WepDecryption():
	'''
	Effettua la decriptazione wep
	Il wep seed viene passato nel costruttore
	'''

	def __init__(self,wepSeed,cipherText):
		self.wepSeed = wepSeed
		self.cipherText = cipherText

	
	def getDecryptedData(self):
		'''
		Se l'ICV è corretto, ritorna i dati decriptati
		@TODO: trovare un modo migliore per separare la tupla nei suoi valori
		'''
		# Creo il cipher
		cipher = arcFour(self.wepSeed)
		cipher.setInput(self.cipherText)
		
		# Decifro
		decriptedTuple = cipher.getOutput()
		
		#print 'Len(ciphertext) = ' + str(len(self.cipherText))
		#print 'Len(plaintext) = ' + str(len(decriptedTuple))
		# separo la tupla nei singoli valori
		p0,p1,p2,p3,p4,p5,p6,p7,p8,p9,p10,p11,p12,p13,p14,p15,p16,p17,p18,p19,p20,p21,p22,p23,p24,p25,p26,p27,p28,p29,p30,p31,p32,p33,p34,p35,p36,p37,p38,p39,p40,p41,p42,p43,p44,p45,p46,p47,p48,p49,p50,p51,p52,p53,p54,p55,p56,p57,p58,p59,p60,p61,p62,p63,p64,p65,p66,p67,p68,p69,p70,p71 = (decriptedTuple)

		# ritorno alla stringa 
		plaintext = struct.pack('<72B',p0,p1,p2,p3,p4,p5,p6,p7,p8,p9,p10,p11,p12,p13,p14,p15,p16,p17,p18,p19,p20,p21,p22,p23,p24,p25,p26,p27,p28,p29,p30,p31,p32,p33,p34,p35,p36,p37,p38,p39,p40,p41,p42,p43,p44,p45,p46,p47,p48,p49,p50,p51,p52,p53,p54,p55,p56,p57,p58,p59,p60,p61,p62,p63,p64,p65,p66,p67,p68,p69,p70,p71)
				
		#prendo plaintext e icv dal pacchetto decritpato		
		payload = plaintext[0:len(plaintext)-4]
		icv = plaintext[len(plaintext)-4:len(plaintext)]

		# calcolo l'icv del pacchetto e controllo che sia uguale all'icv reale
		icv_ok = self.checkICV(payload,icv)

		if icv_ok:
			return plaintext
		else:
			raise WepError('icv_ok','ICV does not match');



	def checkICV(self,plaintext,icv_received_str):
		'''
		Controlla che l'ICV sia corretto
		'''
		# calcola l'icv
		icv_processed = int(binascii.crc32(plaintext) & 0xffffffff)

		# prendo l'icv ricevuto (stringa) e lo converto in numero
		icv_received = struct.unpack('I',icv_received_str)[0]

		#stampa
		print "ICV PROCESSED"
		print (icv_processed)
		print "\nICV RECEIVED"	
		print (icv_received)

		# controllo
		if icv_received == icv_processed:
			return True
		else:	
			return True

	

class WepEncryption():
	'''
	Effettua l'encryption wep
	
	iv, key, plaintext sono tuple
	'''
	def __init__(self,iv,key,plaintext):
		#concateno iv e key
		self.seed = iv + key
		self.plaintext = plaintext

	
	
	def getCiphertext(self):
		'''
		Ritorna il plaintext criptato con wep
		'''		
		#definisco il cipher
		cipher = arcFour(self.seed)
		
		#calcolo il crc32 del plaintext --> intero
		crc32List  = self.crc32()

		#appendo il crc32 al plaintext
		plaintextList = list(self.plaintext)

		#creo la tupla che va in xor con il keystream
		plain = tuple(plaintextList+crc32List)
		
		# faccio lo xor tra il risultato e il keystream
		output = []
		for i in range(len(plain)):
			keyStreamByte = cipher.getKeyStreamByte()	
			outputBlock = plain[i] ^ keyStreamByte
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



