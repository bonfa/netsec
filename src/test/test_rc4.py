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
	Casi di test per le operazioni definite nella classe arcFour
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
		test numero 1 di http://www.freemedialibrary.com/index.php/RC4_test_vectors
		'''
		key = (0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF)
		plainText = (0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF)		
		cipher = arcFour(key)		
		cipher.setInput(plainText)
		processedResult = cipher.getOutput()
		expectedResult = (0x75,0xb7,0x87,0x80,0x99,0xe0,0xc5,0x96)
		self.assertEqual(processedResult,expectedResult) 
		


	def test_4(self):
		'''
		testo la classe arcFour
		test numero 3 di http://www.freemedialibrary.com/index.php/RC4_test_vectors
		'''
		key = (0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)
		plainText = (0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)		
		cipher = arcFour(key)		
		cipher.setInput(plainText)
		processedResult = cipher.getOutput()
		expectedResult = (0xde,0x18,0x89,0x41,0xa3,0x37,0x5d,0x3a)
		self.assertEqual(processedResult,expectedResult) 
		


	def test_5(self):
		'''
		testo la classe arcFour
		test numero 4 di http://www.freemedialibrary.com/index.php/RC4_test_vectors
		'''
		
		key = (0xef,0x01,0x23,0x45)
		plainText = (0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)		
		cipher = arcFour(key)		
		cipher.setInput(plainText)
		processedResult = cipher.getOutput()
		expectedResult = (0xd6,0xa1,0x41,0xa7,0xec,0x3c,0x38,0xdf,0xbd,0x61)
		self.assertEqual(processedResult,expectedResult) 
		


	def test_7(self):
		'''
		testo la classe arcFour
		test numero 6 di http://www.freemedialibrary.com/index.php/RC4_test_vectors
		'''
		key = (0xfb,0x02,0x9e,0x30,0x31,0x32,0x33,0x34)
		plainText = (0xaa,0xaa,0x03,0x00,0x00,0x00,0x08,0x00,0x45,0x00,0x00,0x4e,0x66,0x1a,0x00,0x00,0x80,0x11,0xbe,0x64,0x0a,0x00,0x01,0x22,0x0a,0xff,0xff,0xff,0x00,0x89,0x00,0x89,0x00,0x3a,0x00,0x00,0x80,0xa6,0x01,0x10,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x20,0x45,0x43,0x45,0x4a,0x45,0x48,0x45,0x43,0x46,0x43,0x45,0x50,0x46,0x45,0x45,0x49,0x45,0x46,0x46,0x43,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x41,0x41,0x00,0x00,0x20,0x00,0x01,0x1b,0xd0,0xb6,0x04)	
		cipher = arcFour(key)		
		cipher.setInput(plainText)
		processedResult = cipher.getOutput()
		expectedResult = (0xf6,0x9c,0x58,0x06,0xbd,0x6c,0xe8,0x46,0x26,0xbc,0xbe,0xfb,0x94,0x74,0x65,0x0a,0xad,0x1f,0x79,0x09,0xb0,0xf6,0x4d,0x5f,0x58,0xa5,0x03,0xa2,0x58,0xb7,0xed,0x22,0xeb,0x0e,0xa6,0x49,0x30,0xd3,0xa0,0x56,0xa5,0x57,0x42,0xfc,0xce,0x14,0x1d,0x48,0x5f,0x8a,0xa8,0x36,0xde,0xa1,0x8d,0xf4,0x2c,0x53,0x80,0x80,0x5a,0xd0,0xc6,0x1a,0x5d,0x6f,0x58,0xf4,0x10,0x40,0xb2,0x4b,0x7d,0x1a,0x69,0x38,0x56,0xed,0x0d,0x43,0x98,0xe7,0xae,0xe3,0xbf,0x0e,0x2a,0x2c,0xa8,0xf7)
		self.assertEqual(processedResult,expectedResult)



	def test_8(self):
		'''
		testo la classe arcFour
		test numero 7 di http://www.freemedialibrary.com/index.php/RC4_test_vectors
		'''
		key = (0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF)
		plainText = (0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0,0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0,0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0,0x12,0x34,0x56,0x78)		
		cipher = arcFour(key)		
		cipher.setInput(plainText)
		processedResult = cipher.getOutput()
		expectedResult = (0x66,0xa0,0x94,0x9f,0x8a,0xf7,0xd6,0x89,0x1f,0x7f,0x83,0x2b,0xa8,0x33,0xc0,0x0c,0x89,0x2e,0xbe,0x30,0x14,0x3c,0xe2,0x87,0x40,0x01,0x1e,0xcf)
		self.assertEqual(processedResult,expectedResult)  



	def test_6(self):
		'''
		testo la classe arcFour
		test numero 5 di http://www.freemedialibrary.com/index.php/RC4_test_vectors
		'''
		key = (0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF)
		plainText = (0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01)
		cipher = arcFour(key)		
		cipher.setInput(plainText)
		processedResult = cipher.getOutput()
		expectedResult = (0x75,0x95,0xc3,0xe6,0x11,0x4a,0x09,0x78,0x0c,0x4a,0xd4,0x52,0x33,0x8e,0x1f,0xfd,0x9a,0x1b,0xe9,0x49,0x8f,0x81,0x3d,0x76,0x53,0x34,0x49,0xb6,0x77,0x8d,0xca,0xd8,0xc7,0x8a,0x8d,0x2b,0xa9,0xac,0x66,0x08,0x5d,0x0e,0x53,0xd5,0x9c,0x26,0xc2,0xd1,0xc4,0x90,0xc1,0xeb,0xbe,0x0c,0xe6,0x6d,0x1b,0x6b,0x1b,0x13,0xb6,0xb9,0x19,0xb8,0x47,0xc2,0x5a,0x91,0x44,0x7a,0x95,0xe7,0x5e,0x4e,0xf1,0x67,0x79,0xcd,0xe8,0xbf,0x0a,0x95,0x85,0x0e,0x32,0xaf,0x96,0x89,0x44,0x4f,0xd3,0x77,0x10,0x8f,0x98,0xfd,0xcb,0xd4,0xe7,0x26,0x56,0x75,0x00,0x99,0x0b,0xcc,0x7e,0x0c,0xa3,0xc4,0xaa,0xa3,0x04,0xa3,0x87,0xd2,0x0f,0x3b,0x8f,0xbb,0xcd,0x42,0xa1,0xbd,0x31,0x1d,0x7a,0x43,0x03,0xdd,0xa5,0xab,0x07,0x88,0x96,0xae,0x80,0xc1,0x8b,0x0a,0xf6,0x6d,0xff,0x31,0x96,0x16,0xeb,0x78,0x4e,0x49,0x5a,0xd2,0xce,0x90,0xd7,0xf7,0x72,0xa8,0x17,0x47,0xb6,0x5f,0x62,0x09,0x3b,0x1e,0x0d,0xb9,0xe5,0xba,0x53,0x2f,0xaf,0xec,0x47,0x50,0x83,0x23,0xe6,0x71,0x32,0x7d,0xf9,0x44,0x44,0x32,0xcb,0x73,0x67,0xce,0xc8,0x2f,0x5d,0x44,0xc0,0xd0,0x0b,0x67,0xd6,0x50,0xa0,0x75,0xcd,0x4b,0x70,0xde,0xdd,0x77,0xeb,0x9b,0x10,0x23,0x1b,0x6b,0x5b,0x74,0x13,0x47,0x39,0x6d,0x62,0x89,0x74,0x21,0xd4,0x3d,0xf9,0xb4,0x2e,0x44,0x6e,0x35,0x8e,0x9c,0x11,0xa9,0xb2,0x18,0x4e,0xcb,0xef,0x0c,0xd8,0xe7,0xa8,0x77,0xef,0x96,0x8f,0x13,0x90,0xec,0x9b,0x3d,0x35,0xa5,0x58,0x5c,0xb0,0x09,0x29,0x0e,0x2f,0xcd,0xe7,0xb5,0xec,0x66,0xd9,0x08,0x4b,0xe4,0x40,0x55,0xa6,0x19,0xd9,0xdd,0x7f,0xc3,0x16,0x6f,0x94,0x87,0xf7,0xcb,0x27,0x29,0x12,0x42,0x64,0x45,0x99,0x85,0x14,0xc1,0x5d,0x53,0xa1,0x8c,0x86,0x4c,0xe3,0xa2,0xb7,0x55,0x57,0x93,0x98,0x81,0x26,0x52,0x0e,0xac,0xf2,0xe3,0x06,0x6e,0x23,0x0c,0x91,0xbe,0xe4,0xdd,0x53,0x04,0xf5,0xfd,0x04,0x05,0xb3,0x5b,0xd9,0x9c,0x73,0x13,0x5d,0x3d,0x9b,0xc3,0x35,0xee,0x04,0x9e,0xf6,0x9b,0x38,0x67,0xbf,0x2d,0x7b,0xd1,0xea,0xa5,0x95,0xd8,0xbf,0xc0,0x06,0x6f,0xf8,0xd3,0x15,0x09,0xeb,0x0c,0x6c,0xaa,0x00,0x6c,0x80,0x7a,0x62,0x3e,0xf8,0x4c,0x3d,0x33,0xc1,0x95,0xd2,0x3e,0xe3,0x20,0xc4,0x0d,0xe0,0x55,0x81,0x57,0xc8,0x22,0xd4,0xb8,0xc5,0x69,0xd8,0x49,0xae,0xd5,0x9d,0x4e,0x0f,0xd7,0xf3,0x79,0x58,0x6b,0x4b,0x7f,0xf6,0x84,0xed,0x6a,0x18,0x9f,0x74,0x86,0xd4,0x9b,0x9c,0x4b,0xad,0x9b,0xa2,0x4b,0x96,0xab,0xf9,0x24,0x37,0x2c,0x8a,0x8f,0xff,0xb1,0x0d,0x55,0x35,0x49,0x00,0xa7,0x7a,0x3d,0xb5,0xf2,0x05,0xe1,0xb9,0x9f,0xcd,0x86,0x60,0x86,0x3a,0x15,0x9a,0xd4,0xab,0xe4,0x0f,0xa4,0x89,0x34,0x16,0x3d,0xdd,0xe5,0x42,0xa6,0x58,0x55,0x40,0xfd,0x68,0x3c,0xbf,0xd8,0xc0,0x0f,0x12,0x12,0x9a,0x28,0x4d,0xea,0xcc,0x4c,0xde,0xfe,0x58,0xbe,0x71,0x37,0x54,0x1c,0x04,0x71,0x26,0xc8,0xd4,0x9e,0x27,0x55,0xab,0x18,0x1a,0xb7,0xe9,0x40,0xb0,0xc0)
		self.assertEqual(processedResult,expectedResult) 



if __name__ == '__main__':
	suite = unittest.TestLoader().loadTestsFromTestCase(TestRC4)
	unittest.TextTestRunner(verbosity=2).run(suite)