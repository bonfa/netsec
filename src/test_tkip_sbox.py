#/usr/bin/python
# -*- coding: utf-8 -*-
'''
Testa le operazioni del modulo tkip_sbox
'''
import sys
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src/crypto')
import unittest
import struct
import tkip_sboxes


class SBoxOperation(unittest.TestCase):
	'''
	Casi di test per le operazioni definite nel modulo tkip_sbox
	'''


	def test_getValueFromSbox_1(self):
		'''
		testo l'operazione getValueFromSbox
		'''
		processed = tkip_sboxes.getValueFromSbox(0,0)
		expected = 0xC6A5
		self.assertEqual(expected,processed) 



	def test_getValueFromSbox_2(self):
		'''
		testo l'operazione getValueFromSbox
		'''
		processed = tkip_sboxes.getValueFromSbox(0,255)
		expected = 0x2C3A
		self.assertEqual(expected,processed) 



	def test_getValueFromSbox_3(self):
		'''
		testo l'operazione getValueFromSbox
		'''
		processed = tkip_sboxes.getValueFromSbox(1,0)
		expected = 0xA5C6
		self.assertEqual(expected,processed) 
	


	def test_getValueFromSbox_4(self):
		'''
		testo l'operazione getValueFromSbox
		'''
		processed = tkip_sboxes.getValueFromSbox(1,255)
		expected = 0x3A2C
		self.assertEqual(expected,processed) 

	

	def test_getValueFromSbox_5(self):
		'''
		testo l'operazione getValueFromSbox
		'''
		self.assertRaises(ValueError,tkip_sboxes.getValueFromSbox,-1,214)
		 


	def test_getValueFromSbox_6(self):
		'''
		testo l'operazione getValueFromSbox
		'''
		self.assertRaises(ValueError,tkip_sboxes.getValueFromSbox,0,256)



	def test_getValueFromSbox_7(self):
		'''
		testo l'operazione getValueFromSbox
		'''
		self.assertRaises(ValueError,tkip_sboxes.getValueFromSbox,2,114)



	def test_getValueFromSbox_8(self):
		'''
		testo l'operazione getValueFromSbox
		'''
		self.assertRaises(ValueError,tkip_sboxes.getValueFromSbox,1,-1)



	def test_getValueFromSbox_9(self):
		'''
		testo l'operazione getValueFromSbox
		'''
		self.assertRaises(ValueError,tkip_sboxes.getValueFromSbox,1,257)



	def test_getValueFromSbox_10(self):
		'''
		testo l'operazione getValueFromSbox
		'''
		processed = tkip_sboxes.getValueFromSbox(0,10)
		expected = 0xCEA9
		self.assertEqual(expected,processed)



	def test_S_1(self):
		'''
		testo l'operazione S
		'''
		processed = tkip_sboxes.S(0)
		expected = 0xC6A5 ^ 0xA5C6
		self.assertEqual(expected,processed)



	def test_S_2(self):
		'''
		testo l'operazione S
		'''
		processed = tkip_sboxes.S(0xffff)
		expected = 0x2C3A ^ 0x3A2C
		self.assertEqual(expected,processed)



	def test_S_3(self):
		'''
		testo l'operazione S
		'''
		self.assertRaises(ValueError,tkip_sboxes.S,-1)



	def test_S_4(self):
		'''
		testo l'operazione S
		'''
		self.assertRaises(ValueError,tkip_sboxes.S,2<<16)


if __name__ == '__main__':
	suite = unittest.TestLoader().loadTestsFromTestCase(SBoxOperation)
	unittest.TextTestRunner(verbosity=2).run(suite)
