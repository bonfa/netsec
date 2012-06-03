#/usr/bin/python
# -*- coding: utf-8 -*-
'''
Testa le operazioni della clase base_operation
'''
import sys
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src/crypto')
from four_way_crypto_utility import keyGenerator
import unittest
import struct


class TestKeyGeneration(unittest.TestCase):
	'''
	Casi di test per le operazioni definite nel modulo four_way_crypto_utility
	'''

	
	def setUp(self):
		'''
		definisco il valore dell'input e dell'output in base ai valori della rfc (pag 1139)
		'''
		# Imposto i dati
		self.PMK = struct.pack('32B',0x0d,0xc0,0xd6,0xeb,0x90,0x55,0x5e,0xd6,0x41,0x97,0x56,0xb9,0xa1,0x5e,0xc3,0xe3,0x20,0x9b,0x63,0xdf,0x70,0x7d,0xd5,0x08,0xd1,0x45,0x81,0xf8,0x98,0x27,0x21,0xaf)
		self.AA = struct.pack('6B',0xa0,0xa1,0xa1,0xa3,0xa4,0xa5)
		self.SPA = struct.pack('6B',0xb0,0xb1,0xb2,0xb3,0xb4,0xb5)
		self.SNonce = struct.pack('32B',0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7,0xc8,0xc9,0xd0,0xd1,0xd2,0xd3,0xd4,0xd5,0xd6,0xd7,0xd8,0xd9,0xda,0xdb,0xdc,0xdd,0xde,0xdf,0xe0,0xe1,0xe2,0xe3,0xe4,0xe5)
		self.ANonce = struct.pack('32B',0xe0,0xe1,0xe2,0xe3,0xe4,0xe5,0xe6,0xe7,0xe8,0xe9,0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff,0x00,0x01,0x02,0x03,0x04,0x05)
		self.mex = "Pairwise key expansion"
		# Genero le chiavi
		keyGen = keyGenerator(self.PMK,self.mex,self.AA,self.SPA,self.ANonce,self.SNonce)
		self.kck,self.kek,self.tk,self.authenticatorMicKey,self.supplicantMicKey = keyGen.getKeys()
		# Definisco i risultati corretti
		self.correctKCK = struct.pack('16B',0x37,0x9f,0x98,0x52,0xd0,0x19,0x92,0x36,0xb9,0x4e,0x40,0x7c,0xe4,0xc0,0x0e,0xc8)		
		self.correctKEK = struct.pack('16B',0x47,0xc9,0xed,0xc0,0x1c,0x2c,0x6e,0x5b,0x49,0x10,0xca,0xdd,0xfb,0x3e,0x51,0xa7)
		self.correctTK = struct.pack('32B',0xb2,0x36,0x0c,0x79,0xe9,0x71,0x0f,0xdd,0x58,0xbe,0xa9,0x3d,0xea,0xf0,0x65,0x99,0xdb,0x98,0x0a,0xfb,0xc2,0x9c,0x15,0x28,0x55,0x74,0x0a,0x6c,0xe5,0xae,0x38,0x27)
		self.correctAuthenticatorMicKey = struct.pack('8B',0xdb,0x98,0x0a,0xfb,0xc2,0x9c,0x15,0x28)
		self.correctSupplicantMicKey = struct.pack('8B',0x55,0x74,0x0a,0x6c,0xe5,0xae,0x38,0x27)
		
	
	def testkeyGenerator_KEK(self):
		'''
		testo la correttezza della KEK
		'''
		self.assertEqual(self.kek,self.correctKEK)
	

	def testkeyGenerator_KCK(self):
		'''
		testo la correttezza della KCK
		'''
		self.assertEqual(self.kck,self.correctKCK)


	def testkeyGenerator_TK(self):
		'''
		testo la correttezza della TK
		'''
		self.assertEqual(self.tk,self.correctTK)


	def testkeyGenerator_authenticatorMicKey(self):
		'''
		testo la correttezza della authenticatorMicKey
		'''
		self.assertEqual(self.authenticatorMicKey,self.correctAuthenticatorMicKey)


	def testkeyGenerator_supplicantMicKey(self):
		'''
		testo la correttezza della supplicantMicKey
		'''
		self.assertEqual(self.supplicantMicKey,self.correctSupplicantMicKey)
	



if __name__ == '__main__':
	suite = unittest.TestLoader().loadTestsFromTestCase(TestKeyGeneration)
	unittest.TextTestRunner(verbosity=2).run(suite)