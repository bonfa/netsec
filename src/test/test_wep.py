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



	def testCrc32_3(self):
		'''
		testo il metodo crc32 + il passaggio da tupla a stringa	
		'''
		mexTuple = (0xaa,0xaa,0x03,0x00,0x00,0x00,0x08,0x00,0x45,0x00,0x00,0x4e,0x66,0x1a,0x00,0x00,0x80,0x11,0xbe,0x64,0x0a,0x00,0x01,0x22,0x0a,0xff,0xff,0xff,0x00,0x89,0x00,0x89,0x00,0x3a,0x00,0x00,0x80,0xa6,0x01,0x10,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x20,0x45,0x43,0x45,0x4a,0x45,0x48,0x45,0x43,0x46,0x43,0x45,0x50,0x46,0x45,0x45,0x49,0x45,0x46,0x46,0x43,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x41,0x41,0x00,0x00,0x20,0x00,0x01)

		bytes = array('B',mexTuple[:-1])		
		print bytes
#		mexString = struct.pack('90B',mexTuple)
			
		mexList = list(mexTuple)
		#mexList.reverse()
		mexTupleReversed = tuple(mexList)
		crc32 = wep.crc32(mexTupleReversed)
		resultStr = wep.tupleToString((0x1b,0xd0,0xb6,0x04))
		expectedResult = struct.unpack('>I',resultStr)[0]

		self.assertEqual(crc32,expectedResult) 	
	
	


if __name__ == '__main__':
	suite = unittest.TestLoader().loadTestsFromTestCase(TestWEP)
	unittest.TextTestRunner(verbosity=2).run(suite)
