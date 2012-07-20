#/usr/bin/python
# -*- coding: utf-8 -*-
'''
Testa le operazioni del modulo mic_utilities
'''
import sys
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src/authentication')
from four_way_mic_utility import TkipMicGenerator
import unittest
import struct


class TestTkipMicGenerator(unittest.TestCase):
	'''
	Casi di test per le operazioni definite nel modulo four_way_crypto_utility
	'''


	def test_xswap_1(self):
		'''
		testo la funzione xswap per un numero
		'''
		num = 0x01000001		
		swapped = TkipMicGenerator.xswap(num)
		expected = 0x00010100
		self.assertEqual(expected,swapped) 



	def test_xswap_2(self):
		'''
		testo la funzione xswap per un numero 
		'''
		num = 0xaabbccdd		
		swapped = TkipMicGenerator.xswap(num)
		expected = 0xbbaaddcc
		self.assertEqual(expected,swapped) 



	def test_b_1(self):
		'''
		Test della funzione b utilizzata da Michael per generare il MIC TKIP.
		Test 1 a pagina 1119 della rfc
		'''
		l = 0
		r = 0		
		(l,r) = TkipMicGenerator.b(l,r)
		processedResult = (l,r)
		correctResult = (0,0)
		self.assertEqual(correctResult,processedResult)



	def test_b_2(self):
		'''
		Test della funzione b utilizzata da Michael per generare il MIC TKIP.
		Test 2 a pagina 1119 della rfc
		'''
		l = 0x00000000
		r = 0x00000001
		(l,r) = TkipMicGenerator.b(l,r)
		processedResult = (l,r)
		correctResult = (0xc00015a8,0xc0000b95)
		self.assertEqual(correctResult,processedResult)



	def test_b_3(self):
		'''
		Test della funzione b utilizzata da Michael per generare il MIC TKIP.
		Test 3 a pagina 1119 della rfc
		'''
		l = 0x00000001
		r = 0x00000000
		(l,r) = TkipMicGenerator.b(l,r)
		processedResult = (l,r)
		correctResult = (0x6b519593,0x572b8b8a)
		self.assertEqual(correctResult,processedResult)



	def test_b_4(self):
		'''
		Test della funzione b utilizzata da Michael per generare il MIC TKIP.
		Test 4 a pagina 1119 della rfc
		'''
		l = 0x01234567
		r = 0x83659326
		(l,r) = TkipMicGenerator.b(l,r)
		processedResult = (l,r)
		correctResult = (0x441492c2,0x1d8427ed)
		self.assertEqual(correctResult,processedResult)



	def test_b_5(self):
		'''
		Test della funzione b utilizzata da Michael per generare il MIC TKIP.
		Test 5 a pagina 1119 della rfc
		'''
		l = 0x00000001
		r = 0x00000000
		for i in range(1000):
			(l,r) = TkipMicGenerator.b(l,r)
		processedResult = (l,r)
		correctResult = (0x9f04c4ad,0x2ec6c2bf)
		self.assertEqual(correctResult,processedResult)


	
	def test_michael_1(self):
		'''
		Test dell'algoritmo di michael implementato dalla classe TkipMicGenerator per generare il MIC TKIP.
		Test 1 a pagina 1119 della rfc
		'''
		key = "0000000000000000".decode('hex')
		mex = ""
		correctMic = "82925c1ca1d130b8".decode("hex")
		micGen = TkipMicGenerator(mex,key)
		processedMic = micGen.getMic()
		self.assertEqual(correctMic,processedMic)



	def test_michael_2(self):
		'''
		Test dell'algoritmo di michael implementato dalla classe TkipMicGenerator per generare il MIC TKIP.
		Test 2 a pagina 1119 della rfc
		'''
		key = "82925c1ca1d130b8".decode('hex')
		mex = "M"
		correctMic = "434721ca40639b3f".decode("hex")
		micGen = TkipMicGenerator(mex,key)
		processedMic = micGen.getMic()
		self.assertEqual(correctMic,processedMic)



	def test_michael_3(self):
		'''
		Test dell'algoritmo di michael implementato dalla classe TkipMicGenerator per generare il MIC TKIP.
		Test 3 a pagina 1119 della rfc
		'''
		key = "434721ca40639b3f".decode('hex')
		mex = "Mi"
		correctMic = "e8f9becae97e5d29".decode("hex")
		micGen = TkipMicGenerator(mex,key)
		processedMic = micGen.getMic()
		self.assertEqual(correctMic,processedMic)



	def test_michael_4(self):
		'''
		Test dell'algoritmo di michael implementato dalla classe TkipMicGenerator per generare il MIC TKIP.
		Test 4 a pagina 1119 della rfc
		'''
		key = "e8f9becae97e5d29".decode('hex')
		mex = "Mic"
		correctMic = "90038fc6cf13c1db".decode("hex")
		micGen = TkipMicGenerator(mex,key)
		processedMic = micGen.getMic()
		self.assertEqual(correctMic,processedMic)



	def test_michael_5(self):
		'''
		Test dell'algoritmo di michael implementato dalla classe TkipMicGenerator per generare il MIC TKIP.
		Test 5 a pagina 1119 della rfc
		'''
		key = "90038fc6cf13c1db".decode('hex')
		mex = "Mich"
		correctMic = "D55e100510128986".decode("hex")
		micGen = TkipMicGenerator(mex,key)
		processedMic = micGen.getMic()
		self.assertEqual(correctMic,processedMic)



	def test_michael_6(self):
		'''
		Test dell'algoritmo di michael implementato dalla classe TkipMicGenerator per generare il MIC TKIP.
		Test 6 a pagina 1119 della rfc
		'''
		key = "D55e100510128986".decode('hex')
		mex = "Michael"
		correctMic = "0a942b124ecaa546".decode("hex")
		micGen = TkipMicGenerator(mex,key)
		processedMic = micGen.getMic()
		self.assertEqual(correctMic,processedMic)
	


if __name__ == '__main__':
	suite = unittest.TestLoader().loadTestsFromTestCase(TestTkipMicGenerator)
	unittest.TextTestRunner(verbosity=2).run(suite)
