#/usr/bin/python
# -*- coding: utf-8 -*-
'''
Testa le operazioni della clase base_operation
'''
import sys
sys.path.append('../authentication')
from four_way_crypto_utility import passphraseToPSKMap
import unittest
import struct


class TestPassphraseInPwdMapping(unittest.TestCase):
	'''
	Casi di test per le operazioni definite nel modulo four_way_crypto_utility
	'''
	
	def test_1(self):
		Passphrase = "password"
		SSID = 'IEEE'
		PSK = "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e"
		pskGen = passphraseToPSKMap(Passphrase,SSID)
		psk = pskGen.getPsk()
		hexPsk = psk.encode("hex")
		self.assertEqual(PSK,hexPsk)


	def test_2(self):
		Passphrase = "ThisIsAPassword"
		SSID = 'ThisIsASSID'
		PSK = "0dc0d6eb90555ed6419756b9a15ec3e3209b63df707dd508d14581f8982721af"
		pskGen = passphraseToPSKMap(Passphrase,SSID)
		psk = pskGen.getPsk()
		hexPsk = psk.encode("hex")
		self.assertEqual(PSK,hexPsk)

	def test_3(self):
		Passphrase = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		SSID = 'ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ'
		PSK = "becb93866bb8c3832cb777c2f559807c8c59afcb6eae734885001300a981cc62"
		pskGen = passphraseToPSKMap(Passphrase,SSID)
		psk = pskGen.getPsk()
		hexPsk = psk.encode("hex")
		self.assertEqual(PSK,hexPsk)

	def test_4_mia_psk(self):
		Passphrase = "H6x&@!1uLQ*()!12c0x\\f^\'?|s<SNgh-"
		SSID = 'WWWLAN'
		PSK = "3f4eb9a38ba03f3a28235fd038971be12845a57169c2801d729afa6711f6db96"
		pskGen = passphraseToPSKMap(Passphrase,SSID)
		psk = pskGen.getPsk()
		hexPsk = psk.encode("hex")
		self.assertEqual(PSK,hexPsk)


if __name__ == '__main__':
	suite = unittest.TestLoader().loadTestsFromTestCase(TestPassphraseInPwdMapping)
	unittest.TextTestRunner(verbosity=2).run(suite)
