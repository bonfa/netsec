#/usr/bin/python
# -*- coding: utf-8 -*-
'''
Testa le operazioni della clase base_operation
'''
import sys
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src/crypto')
from four_way_crypto_utility import keyGenerator
import unittest
#sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src/crypto')


class TestKeyGeneration(unittest.TestCase):
	'''
	Casi di test per le operazioni definite nel modulo four_way_crypto_utility
	'''

	
	def testkeyGenerator(self):
		'''
		testo l'operazione di generazione chiavi con l'unico valore a disposizione che è quello della rfc
		'''
		# Imposto i dati
		PMK = '0dc0d6eb90555ed6419756b9a15ec3e3209b63df707dd508d14581f8982721af'
		AA = 'a0a1a1a3a4a5'
		SPA = 'b0b1b2b3b4b5'
		SNonce = 'c0c1c2c3c4c5c6c7c8c9d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5'
		ANonce = 'e0e1e2e3e4e5e6e7e8e9f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405'
		mex = "Pairwise key expansion"

		print len(PMK)
		for i in range(0,len(PMK)):
			print bin(i)
		# Genero le chiavi
		keyGen = keyGenerator(PMK,mex,AA,SPA,ANonce,SNonce,512)
		kek,kck,tk,micKey1,micKey2 = keyGen.getKeys()
		
		# Controllo i risultati
		self.assertEqual(kek,'47c9edc01c2c6e5b4910caddfb3e51a7')
		#self.assertEqual(kck,'379f9852d0199236b94e407ce4c00ec8')
		#self.assertEqual(tk,'b2360c79e9710fdd58bea93deaf06599')
		#self.assertEqual(micKey1,'db980afbc29c1528')
		#self.assertEqual(micKey2,'55740a6ce5ae3827')
	


if __name__ == '__main__':
	suite = unittest.TestLoader().loadTestsFromTestCase(TestKeyGeneration)
	unittest.TextTestRunner(verbosity=2).run(suite)
