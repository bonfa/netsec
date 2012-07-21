#/usr/bin/python
# -*- coding: utf-8 -*-
'''
Testa le operazioni del modulo rc4
OSS: nei test del crc-32 il pack viene fatto in modi diversi (vedi 'testCrc32_2' e 'testCrc32_3' --> struct.unpack) 
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

		crc32 = wep.crc32Value(mexTuple)
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

		crc32 = wep.crc32Value(mexTuple)
		resultStr = wep.tupleToString((0x0c,0x87,0x7f,0x61))
		expectedResult = struct.unpack('>I',resultStr)[0]

		self.assertEqual(crc32,expectedResult) 



	def testCrc32_3(self):
		'''
		testo il metodo crc32 + il passaggio da tupla a stringa	
		'''
		mexTuple = (0xaa,0xaa,0x03,0x00,0x00,0x00,0x08,0x00,0x45,0x00,0x00,0x4e,0x66,0x1a,0x00,0x00,0x80,0x11,0xbe,0x64,0x0a,0x00,0x01,0x22,0x0a,0xff,0xff,0xff,0x00,0x89,0x00,0x89,0x00,0x3a,0x00,0x00,0x80,0xa6,0x01,0x10,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x20,0x45,0x43,0x45,0x4a,0x45,0x48,0x45,0x43,0x46,0x43,0x45,0x50,0x46,0x45,0x45,0x49,0x45,0x46,0x46,0x43,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x41,0x41,0x00,0x00,0x20,0x00,0x01)

		crc32 = wep.crc32Value(mexTuple)
		resultStr = wep.tupleToString((0x1b,0xd0,0xb6,0x04))
		expectedResult = struct.unpack('I',resultStr)[0]
	
		self.assertEqual(crc32,expectedResult) 	
	
	
	
	def test_WEP_encryption_1(self):
		'''
		testo la classe wep.WepEncryption tramite i test vector di arc4
		test numero 1 di pag 7 di "draft-kaukonen-cipher-arcfour-01"
		'''
		iv = (0x01,0x23,0x45,0x67)
		key = (0x89,0xAB,0xCD,0xEF)
		plainText = (0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)		
		encryptor = wep.WepEncryption(iv,key,plainText)
		encrypted = encryptor.getCiphertext()	
		##Tolgo l'encryption del crc
		processedResult = encrypted[:len(encrypted)-4]
		expectedResult = (0x74,0x94,0xC2,0xE7,0x10,0x4B,0x08,0x79)
		self.assertEqual(processedResult,expectedResult)



	def test_WEP_encryption_2(self):
		'''
		testo la classe wep.WepEncryption tramite i test vector di arc4
		test numero 2 di pag 7 di "draft-kaukonen-cipher-arcfour-01"
		'''
		iv = ()
		key = (0x61,0x8a,0x63,0xd2,0xfb)
		plainText = (0xdc,0xee,0x4c,0xf9,0x2c)		
		encryptor = wep.WepEncryption(iv,key,plainText)
		encrypted = encryptor.getCiphertext()	
		##Tolgo l'encryption del crc
		processedResult = encrypted[:len(encrypted)-4]
		expectedResult = (0xf1,0x38,0x29,0xc9,0xde)
		self.assertEqual(processedResult,expectedResult) 




	def test_WEP_encryption_3(self):
		'''
		testo la classe wep.WepEncryption tramite i test vector di arc4
		test numero 1 di http://www.freemedialibrary.com/index.php/RC4_test_vectors
		'''
		iv = ()
		key = (0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF)
		plainText = (0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF)		
		encryptor = wep.WepEncryption(iv,key,plainText)
		encrypted = encryptor.getCiphertext()	
		##Tolgo l'encryption del crc
		processedResult = encrypted[:len(encrypted)-4]
		expectedResult = (0x75,0xb7,0x87,0x80,0x99,0xe0,0xc5,0x96)
		self.assertEqual(processedResult,expectedResult) 
		


	def test_WEP_encryption_4(self):
		'''
		testo la classe wep.WepEncryption tramite i test vector di arc4
		test numero 3 di http://www.freemedialibrary.com/index.php/RC4_test_vectors
		'''
		iv = ()
		key = (0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)
		plainText = (0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)		
		encryptor = wep.WepEncryption(iv,key,plainText)
		encrypted = encryptor.getCiphertext()	
		##Tolgo l'encryption del crc
		processedResult = encrypted[:len(encrypted)-4]
		expectedResult = (0xde,0x18,0x89,0x41,0xa3,0x37,0x5d,0x3a)
		self.assertEqual(processedResult,expectedResult)




	def test_WEP_encryption_5(self):
		'''
		testo la classe wep.WepEncryption tramite i test vector di arc4
		test numero 6 di http://www.freemedialibrary.com/index.php/RC4_test_vectors
		'''
		iv = ()
		key = (0xfb,0x02,0x9e,0x30,0x31,0x32,0x33,0x34)
		plainText = (0xaa,0xaa,0x03,0x00,0x00,0x00,0x08,0x00,0x45,0x00,0x00,0x4e,0x66,0x1a,0x00,0x00,0x80,0x11,0xbe,0x64,0x0a,0x00,0x01,0x22,0x0a,0xff,0xff,0xff,0x00,0x89,0x00,0x89,0x00,0x3a,0x00,0x00,0x80,0xa6,0x01,0x10,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x20,0x45,0x43,0x45,0x4a,0x45,0x48,0x45,0x43,0x46,0x43,0x45,0x50,0x46,0x45,0x45,0x49,0x45,0x46,0x46,0x43,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x41,0x41,0x00,0x00,0x20,0x00,0x01,0x1b,0xd0,0xb6,0x04)	
		encryptor = wep.WepEncryption(iv,key,plainText)
		encrypted = encryptor.getCiphertext()	
		##Tolgo l'encryption del crc
		processedResult = encrypted[:len(encrypted)-4]
		expectedResult = (0xf6,0x9c,0x58,0x06,0xbd,0x6c,0xe8,0x46,0x26,0xbc,0xbe,0xfb,0x94,0x74,0x65,0x0a,0xad,0x1f,0x79,0x09,0xb0,0xf6,0x4d,0x5f,0x58,0xa5,0x03,0xa2,0x58,0xb7,0xed,0x22,0xeb,0x0e,0xa6,0x49,0x30,0xd3,0xa0,0x56,0xa5,0x57,0x42,0xfc,0xce,0x14,0x1d,0x48,0x5f,0x8a,0xa8,0x36,0xde,0xa1,0x8d,0xf4,0x2c,0x53,0x80,0x80,0x5a,0xd0,0xc6,0x1a,0x5d,0x6f,0x58,0xf4,0x10,0x40,0xb2,0x4b,0x7d,0x1a,0x69,0x38,0x56,0xed,0x0d,0x43,0x98,0xe7,0xae,0xe3,0xbf,0x0e,0x2a,0x2c,0xa8,0xf7)
		self.assertEqual(processedResult,expectedResult)



	def test_WEP_encryption_6(self):
		'''
		testo la classe wep.WepEncryption tramite i test vector di arc4
		test numero 7 di http://www.freemedialibrary.com/index.php/RC4_test_vectors
		'''
		iv = ()
		key = (0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF)
		plainText = (0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0,0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0,0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0,0x12,0x34,0x56,0x78)		
		encryptor = wep.WepEncryption(iv,key,plainText)
		encrypted = encryptor.getCiphertext()	
		##Tolgo l'encryption del crc
		processedResult = encrypted[:len(encrypted)-4]
		expectedResult = (0x66,0xa0,0x94,0x9f,0x8a,0xf7,0xd6,0x89,0x1f,0x7f,0x83,0x2b,0xa8,0x33,0xc0,0x0c,0x89,0x2e,0xbe,0x30,0x14,0x3c,0xe2,0x87,0x40,0x01,0x1e,0xcf)
		self.assertEqual(processedResult,expectedResult)


	
	def test_WEP_decryption_complete_1(self):
		'''
		testo la classe wep.WepDecryption
		test pagina 1134 della rfc 802.11-2007
		'''
		iv = (0xfb,0x02,0x9e,0x80)
		key = (0x30,0x31,0x32,0x33,0x34)
		ciphertext = (0xf6,0x9c,0x58,0x06,0xbd,0x6c,0xe8,0x46,0x26,0xbc,0xbe,0xfb,0x94,0x74,0x65,0x0a,0xad,0x1f,0x79,0x09,0xb0,0xf6,0x4d,0x5f,0x58,0xa5,0x03,0xa2,0x58,0xb7,0xed,0x22,0xeb,0x0e,0xa6,0x49,0x30,0xd3,0xa0,0x56,0xa5,0x57,0x42,0xfc,0xce,0x14,0x1d,0x48,0x5f,0x8a,0xa8,0x36,0xde,0xa1,0x8d,0xf4,0x2c,0x53,0x80,0x80,0x5a,0xd0,0xc6,0x1a,0x5d,0x6f,0x58,0xf4,0x10,0x40,0xb2,0x4b,0x7d,0x1a,0x69,0x38,0x56,0xed,0x0d,0x43,0x98,0xe7,0xae,0xe3,0xbf,0x0e,0x2a,0x2c,0xa8,0xf7) 
	
		decryptor = wep.WepDecryption(iv[:3],key,ciphertext)
		decrypted = decryptor.getPlaintextAndIcv()	
		##Tolgo l'encryption del crc
		processedResult = decrypted
		expectedResult = (0xaa,0xaa,0x03,0x00,0x00,0x00,0x08,0x00,0x45,0x00,0x00,0x4e,0x66,0x1a,0x00,0x00,0x80,0x11,0xbe,0x64,0x0a,0x00,0x01,0x22,0x0a,0xff,0xff,0xff,0x00,0x89,0x00,0x89,0x00,0x3a,0x00,0x00,0x80,0xa6,0x01,0x10,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x20,0x45,0x43,0x45,0x4a,0x45,0x48,0x45,0x43,0x46,0x43,0x45,0x50,0x46,0x45,0x45,0x49,0x45,0x46,0x46,0x43,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x41,0x41,0x00,0x00,0x20,0x00,0x01,0x1b,0xd0,0xb6,0x04)
		self.assertEqual(processedResult,expectedResult)



	def test_WEP_encryption_complete_1(self):
		'''
		testo la classe wep.WepEncryption
		test pagina 1134 della rfc 802.11-2007
		'''
		iv = (0xfb,0x02,0x9e)		
		key = (0x30,0x31,0x32,0x33,0x34)
		plaintext = (0xaa,0xaa,0x03,0x00,0x00,0x00,0x08,0x00,0x45,0x00,0x00,0x4e,0x66,0x1a,0x00,0x00,0x80,0x11,0xbe,0x64,0x0a,0x00,0x01,0x22,0x0a,0xff,0xff,0xff,0x00,0x89,0x00,0x89,0x00,0x3a,0x00,0x00,0x80,0xa6,0x01,0x10,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x20,0x45,0x43,0x45,0x4a,0x45,0x48,0x45,0x43,0x46,0x43,0x45,0x50,0x46,0x45,0x45,0x49,0x45,0x46,0x46,0x43,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x41,0x41,0x00,0x00,0x20,0x00,0x01)
		encryptor = wep.WepEncryption(iv,key,plaintext)
		encrypted = encryptor.getCiphertext()
		processedResult = encrypted
		expectedResult = (0xf6,0x9c,0x58,0x06,0xbd,0x6c,0xe8,0x46,0x26,0xbc,0xbe,0xfb,0x94,0x74,0x65,0x0a,0xad,0x1f,0x79,0x09,0xb0,0xf6,0x4d,0x5f,0x58,0xa5,0x03,0xa2,0x58,0xb7,0xed,0x22,0xeb,0x0e,0xa6,0x49,0x30,0xd3,0xa0,0x56,0xa5,0x57,0x42,0xfc,0xce,0x14,0x1d,0x48,0x5f,0x8a,0xa8,0x36,0xde,0xa1,0x8d,0xf4,0x2c,0x53,0x80,0x80,0x5a,0xd0,0xc6,0x1a,0x5d,0x6f,0x58,0xf4,0x10,0x40,0xb2,0x4b,0x7d,0x1a,0x69,0x38,0x56,0xed,0x0d,0x43,0x98,0xe7,0xae,0xe3,0xbf,0x0e,0x2a,0x2c,0xa8,0xf7) 
		self.assertEqual(processedResult,expectedResult)
		


if __name__ == '__main__':
	suite = unittest.TestLoader().loadTestsFromTestCase(TestWEP)
	unittest.TextTestRunner(verbosity=2).run(suite)
