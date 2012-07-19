#/usr/bin/python
# -*- coding: utf-8 -*-

'''
Effettua le due operazioni di encryption e decryption del wep
'''

import binascii
from exception import WepError
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

	def __init__(self,wepSeed,cipherText,icv_received):
		self.wepSeed = wepSeed
		self.cipherText = cipherText
		self.icv_received = icv_received

	
	def getDecryptedData(self):
		'''
		Se l'ICV è corretto, ritorna i dati decriptati
		@TODO: trovare un modo migliore per separare la tupla nei suoi valori
		'''
		# Creo il cipher
		cipher = arcFour(self.wepSeed)
		cipher.setInput(self.cipherText)
		# effettuo la cifratura
		decriptedTuple = cipher.getOutput()
		
		print 'Len(ciphertext) = ' + str(len(self.cipherText))
		print 'Len(plaintext) = ' + str(len(decriptedTuple))
		# separo la tupla nei singoli valori
		p0,p1,p2,p3,p4,p5,p6,p7,p8,p9,p10,p11,p12,p13,p14,p15,p16,p17,p18,p19,p20,p21,p22,p23,p24,p25,p26,p27,p28,p29,p30,p31,p32,p33,p34,p35,p36,p37,p38,p39,p40,p41,p42,p43,p44,p45,p46,p47,p48,p49,p50,p51,p52,p53,p54,p55,p56,p57,p58,p59,p60,p61,p62,p63,p64,p65,p66,p67,p68,p69,p70,p71 = (decriptedTuple)

		# ritorno alla stringa 
		plaintext = struct.pack('<72B',p0,p1,p2,p3,p4,p5,p6,p7,p8,p9,p10,p11,p12,p13,p14,p15,p16,p17,p18,p19,p20,p21,p22,p23,p24,p25,p26,p27,p28,p29,p30,p31,p32,p33,p34,p35,p36,p37,p38,p39,p40,p41,p42,p43,p44,p45,p46,p47,p48,p49,p50,p51,p52,p53,p54,p55,p56,p57,p58,p59,p60,p61,p62,p63,p64,p65,p66,p67,p68,p69,p70,p71)
				
		# calcolo l'icv del pacchetto e controllo che sia uguale all'icv reale
		icv_ok = self.checkICV(plaintext)

		if icv_ok:
			return plaintext
		else:
			raise WepError('icv_ok','ICV does not match');



	def checkICV(self,plaintext):
		'''
		Controlla che l'ICV sia corretto
		'''
		#calcola l'icv
		icv_processed = binascii.crc32(plaintext) & 0xffffffff
		#stampa
		print "ICV PROCESSED"
		print (icv_processed)
		print "\nICV RECEIVED"	
		print (self.icv_received)
		# controllo
		if self.icv_received == icv_processed:
			return True
		else:	
			return True

	

	
		

