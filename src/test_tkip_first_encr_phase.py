#/usr/bin/python
# -*- coding: utf-8 -*-
'''
Testa le operazioni del modulo tkip_encryption
'''
import sys
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src/crypto')
from tkip_encryption import TKIPphaseOne
import unittest
import struct



class TestTkipEncryptionPhaseOne(unittest.TestCase):
	'''
	Casi di test per le operazioni definite nella classe TKIPphaseOne
	'''


	def test_mk16_1(self):
		'''
		testo la funzione mk16 per due valori
		'''
		a = 0
		b = 0
		processedResult = TKIPphaseOne.mk16(a,b)
		expectedResult = 0
		self.assertEqual(processedResult,expectedResult) 



	def test_mk16_2(self):
		'''
		testo la funzione mk16 per due valori
		'''
		a = 0xaa
		b = 0x00
		processedResult = TKIPphaseOne.mk16(a,b)
		expectedResult = 0xaa00
		self.assertEqual(processedResult,expectedResult)



	def test_mk16_3(self):
		'''
		testo la funzione mk16 per due valori
		'''
		a = 0x1f
		b = 0x02
		processedResult = TKIPphaseOne.mk16(a,b)
		expectedResult = 0x1f02
		self.assertEqual(processedResult,expectedResult) 



	def test_getSplittedTA(self):
		'''
		testo la funzione che separa il TA
		'''
		tk = 0
		ta = struct.pack('6B',0xaa,0xbb,0xcc,0xdd,0xee,0xff)
		tsc = 0
		encrPh1 = TKIPphaseOne(tk,ta,tsc)
		processedResult = encrPh1.getSplittedTA()
		expectedResult = (0xaa,0xbb,0xcc,0xdd,0xee,0xff)
		self.assertEqual(processedResult,expectedResult) 



	def test_getSplittedTK(self):
		'''
		testo la funzione che separa la TK
		'''
		tk = struct.pack('16B',0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff)
		ta = 0
		tsc = 0
		encrPh1 = TKIPphaseOne(tk,ta,tsc)
		processedResult = encrPh1.getSplittedTK()
		expectedResult = (0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff)
		self.assertEqual(processedResult,expectedResult) 



	def test_getSplittedTSC(self):
		'''
		testo la funzione che separa la TSC
		'''
		tk = 0
		ta = 0
		tsc = struct.pack('6B',0x00,0x11,0x22,0x33,0x44,0x55)
		encrPh1 = TKIPphaseOne(tk,ta,tsc)
		processedResult = encrPh1.getSplittedTSC()
		expectedResult = (0x00,0x11,0x22,0x33,0x44,0x55)
		self.assertEqual(processedResult,expectedResult) 



	def test_phaseOne_1(self):
		'''
		testo la classe che effettua la prima parte della mixing function
		'''
		tk = struct.pack('16B',0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F)
		ta = struct.pack('6B',0x10,0x22,0x33,0x44,0x55,0x66)
		tsc = struct.pack('6B',0x00,0x00,0x00,0x00,0x00,0x00)
		expectedResult = (0x3DD2,0x016E,0x76F4,0x8697,0xB2E8)
		encrPh1 = TKIPphaseOne(tk,ta,tsc)
		processedResult = encrPh1.getTTAK()
		self.assertEqual(processedResult,expectedResult)



	def test_phaseOne_2(self):
		'''
		testo la classe che effettua la prima parte della mixing function
		'''
		tk = struct.pack('16B',0x63,0x89,0x3B,0x25,0x08,0x40,0xB8,0xAE,0x0B,0xD0,0xFA,0x7E,0x61,0xD2,0x78,0x3E)
		ta = struct.pack('6B',0x64,0xF2,0xEA,0xED,0xDC,0x25)
		tsc = struct.pack('6B',0xFF,0xFF,0x43,0xFD,0xDC,0x20)
		expectedResult = (0x7C67,0x49D7,0x9724,0xB5E9,0xB4F1)
		encrPh1 = TKIPphaseOne(tk,ta,tsc)
		processedResult = encrPh1.getTTAK()
		self.assertEqual(processedResult,expectedResult)


	
	def test_phaseOne_3(self):
		'''
		testo la classe che effettua la prima parte della mixing function
		'''
		tk = struct.pack('16B',0x98,0x3A,0x16,0xEF,0x4F,0xAC,0xB3,0x51,0xAA,0x9E,0xCC,0x27,0x1D,0x73,0x09,0xE2)
		ta = struct.pack('6B',0x50,0x9C,0x4B,0x17,0x27,0xD9)
		tsc = struct.pack('6B',0x8C,0x05,0xFC,0x10,0xA4,0xF0)
		expectedResult = (0xF2DF,0xEBB1,0x88D3,0x5923,0xA07C)
		encrPh1 = TKIPphaseOne(tk,ta,tsc)
		processedResult = encrPh1.getTTAK()
		self.assertEqual(processedResult,expectedResult)



	def test_phaseOne_4(self):
		'''
		testo la classe che effettua la prima parte della mixing function
		'''
		tk = struct.pack('16B',0xC8,0xAD,0xC1,0x6A,0x8B,0x4D,0xDA,0x3B,0x4D,0xD5,0xB6,0x54,0x38,0x35,0x9B,0x05)
		ta = struct.pack('6B',0x94,0x5E,0x24,0x4E,0x4D,0x6E)
		tsc = struct.pack('6B',0XF9,0x30,0xB7,0x73,0x15,0x8B)
		expectedResult = (0xEFF1,0x3F38,0xA364,0x60A9,0x76F3)
		encrPh1 = TKIPphaseOne(tk,ta,tsc)
		processedResult = encrPh1.getTTAK()
		self.assertEqual(processedResult,expectedResult)



if __name__ == '__main__':
	suite = unittest.TestLoader().loadTestsFromTestCase(TestTkipEncryptionPhaseOne)
	unittest.TextTestRunner(verbosity=2).run(suite)
