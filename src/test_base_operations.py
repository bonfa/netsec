#/usr/bin/python
# -*- coding: utf-8 -*-
'''
Testa le operazioni della clase base_operation
'''
import sys
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src/common_utility')
from base_operations import leftRotationOperation,rightRotationOperation,NegativeShiftValueException
import unittest
import struct


class TestBaseOperation(unittest.TestCase):
	'''
	Casi di test per le operazioni definite nel modulo base_operation
	'''


	def setUp(self):
		'''
		definisco il valore della variabile a
		'''
		self.a = 0b00000000111111111010101011111111

##^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-+

	def testRightRotationOperationWithNegativeShift(self):
		'''
		testo l'operazione di rotazione a destra di un valore negativo
		'''
		#r = rightRotationOperation(self.a,-1)
		shiftValue = -2
		self.assertRaises(NegativeShiftValueException,rightRotationOperation,self.a,shiftValue)


	def testRightRotationOperationWithoutRotation(self):
		'''
		testo l'operazione di rotazione a destra di un valore zero
		'''
		r = rightRotationOperation(self.a,0)
		self.assertEqual(self.a,r)


	def testRightRotationOperationWithShift1(self):
		'''
		testo l'operazione di rotazione a destra di 1 bit
		'''
		r = rightRotationOperation(self.a,1)
		result = 0b10000000011111111101010101111111	
		self.assertEqual(result,r)
	

	def testRightRotationOperationWithShiftMinorThanBits(self):
		'''
		testo l'operazione di rotazione a destra di un valore diverso da zero (e minore di 32)
		'''
		r = rightRotationOperation(self.a,17)
		result = 0b11010101011111111000000001111111	
		self.assertEqual(result,r)


	def testRightRotationOperationWithShift31(self):
		'''
		testo l'operazione di rotazione a destra di 31 bit
		'''
		r = rightRotationOperation(self.a,31)
		result = 0b00000001111111110101010111111110
		self.assertEqual(result,r)	


	def testRightRotationOperationWithShiftEqualToBits(self):
		'''
		testo l'operazione di rotazione a destra di un valore uguale al numero di bits
		'''
		r = rightRotationOperation(self.a,32)
		self.assertEqual(self.a,r)

	
	def testRightRotationOperationWithShift33(self):
		'''
		testo l'operazione di rotazione a destra di 33 bit
		'''
		r = rightRotationOperation(self.a,33)
		result = 0b10000000011111111101010101111111
		self.assertEqual(result,r)


	def testRightRotationOperationWithShiftMajorThanBits(self):
		'''
		testo l'operazione di rotazione a destra di un valore maggiore di 32 bit
		'''
		r = rightRotationOperation(self.a,49)
		result = 0b11010101011111111000000001111111
		self.assertEqual(result,r)

##^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-
	def testLeftRotationOperationWithNegativeShift(self):
		'''
		testo l'operazione di rotazione a sinistra di un valore negativo
		'''
		#r = rightRotationOperation(self.a,-1)
		shiftValue = -2
		self.assertRaises(NegativeShiftValueException,leftRotationOperation,self.a,shiftValue)


	def testLeftRotationOperationWithoutRotation(self):
		'''
		testo l'operazione di rotazione a Sinistra di un valore uguale a 0
		'''
		l = leftRotationOperation(self.a,0)
		self.assertEqual(self.a,l)

	
	def testLeftRotationOperationWithShift1(self):
		'''
		testo l'operazione di rotazione a sinistra di un valore uguale a 1
		'''
		l = leftRotationOperation(self.a,1)
		result = 0b00000001111111110101010111111110
		self.assertEqual(result,l)


	def testLeftRotationOperationWithShiftMinorThanBits(self):
		'''
		testo l'operazione di rotazione a sinistra di un valore diverso da zero e minore di 32
		'''
		l = leftRotationOperation(self.a,17)
		result = 0b01010101111111100000000111111111
		self.assertEqual(result,l)	


	def testLeftRotationOperationWithShift31(self):
		'''
		testo l'operazione di rotazione a sinistra di un valore uguale a 31
		'''
		l = leftRotationOperation(self.a,31)
		result = 0b10000000011111111101010101111111
		self.assertEqual(result,l)
	

	def testLeftRotationOperationWithShiftEqualToBits(self):
		'''
		testo l'operazione di rotazione a sinistra di un valore uguale al numero di bits (32)
		'''
		l = leftRotationOperation(self.a,32)
		self.assertEqual(self.a,l)
	
	
	def testLeftRotationOperationWithShift33(self):
		'''
		testo l'operazione di rotazione a sinistra di un valore uguale a 33
		'''
		l = leftRotationOperation(self.a,33)
		result = 0b00000001111111110101010111111110
		self.assertEqual(result,l)


	def testLeftRotationOperationWithShiftMajorThanBits(self):
		'''
		testo l'operazione di rotazione a sinistra di un valore diverso da zero e maggiore di 32
		'''
		l = leftRotationOperation(self.a,49)
		result = 0b01010101111111100000000111111111
		self.assertEqual(result,l)



if __name__ == '__main__':
	suite = unittest.TestLoader().loadTestsFromTestCase(TestBaseOperation)
	unittest.TextTestRunner(verbosity=2).run(suite)
