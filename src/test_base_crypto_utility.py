#/usr/bin/python
# -*- coding: utf-8 -*-
'''
Testa le operazioni della clase crypto_utility
'''
import sys
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src/crypto')
import base_crypto_utility
import unittest



class TestKeyGeneration(unittest.TestCase):
	'''
	Casi di test per le operazioni definite nel modulo base_crypto_utility.py
	'''

	def testPrf(self):
		'''
		testo la funzione prf con 
		'''
		key = "Jefe"
		#Keylength = 20
		prefix = "prefix"
		#PrefixLength = 6
		data = "what do ya want for nothing?"
		#DataLength = 8
		length = 512/8
		prf = base_crypto_utility.prf(key,prefix,data,length)
		result = '\x51\xf4\xde\x5b\x33\xf2\x49\xad\xf8\x1a\xeb\x71\x3a\x3c\x20\xf4\xfe\x63\x14\x46\xfa\xbd\xfa\x58\x24\x47\x59\xae\x58\xef\x90\x09\xa9\x9a\xbf\x4e\xac\x2c\xa5\xfa\x87\xe6\x92\xc4\x40\xeb\x40\x02\x3e\x7b\xab\xb2\x06\xd6\x1d\xe7\xb9\x2f\x41\x52\x90\x92\xb8\xfc'
		self.assertEqual(prf,result)
	


if __name__ == '__main__':
	suite = unittest.TestLoader().loadTestsFromTestCase(TestKeyGeneration)
	unittest.TextTestRunner(verbosity=2).run(suite)
