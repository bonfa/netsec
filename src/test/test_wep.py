#/usr/bin/python
# -*- coding: utf-8 -*-
'''
Testa le operazioni del modulo rc4
OSS: in tutti i test il tsc è definito con i byte inversi rispetto al test vector
'''
import sys
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src/crypto')
import wep
import unittest
import struct
import binascii
import array


class TestWEP(unittest.TestCase):
	'''
	Casi di test per le operazioni definite nel modulo WEP
	'''


	def testBinasciiCRC_1(self):
		'''
		testo il metodo crc32
		test 1 http://www.febooti.com/products/filetweak/members/hash-and-crc/test-vectors/
		'''
		mexStr = ""
		crc32 = binascii.crc32(mexStr)
		expectedResult = 0
		self.assertEqual(crc32,expectedResult) 



	def testBinasciiCRC_2(self):
		'''
		testo il metodo crc32
		test 2 http://www.febooti.com/products/filetweak/members/hash-and-crc/test-vectors/
		'''
		mexStr = "Test vector from febooti.com"
		crc32 = binascii.crc32(mexStr)
		resultStr = wep.tupleToString((0x0c,0x87,0x7f,0x61))
		expectedResult = struct.unpack('>I',resultStr)[0]
		self.assertEqual(crc32,expectedResult) 


	
	def testCrc32_1(self):
		'''
		testo il metodo crc32 + il passaggio da tupla a stringa
		test 1 http://www.febooti.com/products/filetweak/members/hash-and-crc/test-vectors/
		'''
		mexStr = ""
		mexTuple = struct.unpack('0B',mexStr)

		crc32 = wep.crc32(mexTuple)
		resultStr = wep.tupleToString((0x00,0x00,0x00,0x00))
		expectedResult = struct.unpack('>I',resultStr)[0]

		self.assertEqual(crc32,expectedResult) 



	def testCrc32_2(self):
		'''
		testo il metodo crc32 + il passaggio da tupla a stringa
		test 2 http://www.febooti.com/products/filetweak/members/hash-and-crc/test-vectors/
		'''
		mexStr = "Test vector from febooti.com"
		mexTuple = struct.unpack('28B',mexStr)

		crc32 = wep.crc32(mexTuple)
		resultStr = wep.tupleToString((0x0c,0x87,0x7f,0x61))
		expectedResult = struct.unpack('>I',resultStr)[0]

		self.assertEqual(crc32,expectedResult) 



	
	


if __name__ == '__main__':
	suite = unittest.TestLoader().loadTestsFromTestCase(TestWEP)
	unittest.TextTestRunner(verbosity=2).run(suite)
