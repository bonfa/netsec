#/usr/bin/python
# -*- coding: utf-8 -*-
'''
Testa le operazioni del modulo rc4
OSS: in tutti i test il tsc è definito con i byte inversi rispetto al test vector
'''
import sys
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src/crypto')
from rc4 import arcFour
import unittest
import struct



class TestRC4(unittest.TestCase):
	'''
	Casi di test per le operazioni definite nella classe TKIPphaseOne
	'''


	def test_1(self):
		'''
		testo la classe arcFour
		test numero 1 di pag 7 di "draft-kaukonen-cipher-arcfour-01"
		'''
		key = (0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF)
		plainText = (0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)		
		cipher = arcFour(key)		
		cipher.setInput(plainText)
		processedResult = cipher.getOutput()
		expectedResult = (0x74,0x94,0xC2,0xE7,0x10,0x4B,0x08,0x79)
		self.assertEqual(processedResult,expectedResult) 



	def test_2(self):
		'''
		testo la classe arcFour
		test numero 2 di pag 7 di "draft-kaukonen-cipher-arcfour-01"
		'''
		key = (0x61,0x8a,0x63,0xd2,0xfb)
		plainText = (0xdc,0xee,0x4c,0xf9,0x2c)		
		cipher = arcFour(key)		
		cipher.setInput(plainText)
		processedResult = cipher.getOutput()
		expectedResult = (0xf1,0x38,0x29,0xc9,0xde)
		self.assertEqual(processedResult,expectedResult) 




	def test_3(self):
		'''
		testo la classe arcFour
		test numero 3 di pag 7 di "draft-kaukonen-cipher-arcfour-01"
		'''
		'''
		key = (0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF)
		plainText = (0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)		
		cipher = arcFour(key)		
		cipher.setInput(plainText)
		processedResult = cipher.getOutput()
		expectedResult = (0x74,0x94,0xC2,0xE7,0x10,0x4B,0x08,0x79)
		self.assertEqual(processedResult,expectedResult) 
		'''





if __name__ == '__main__':
	suite = unittest.TestLoader().loadTestsFromTestCase(TestRC4)
	unittest.TextTestRunner(verbosity=2).run(suite)
