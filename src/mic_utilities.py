#/usr/bin/python
# -*- coding: utf-8 -*-
'''
Contiene le utility necessarie a effettuare il MIC del 4 way handshake
'''

import struct
from exception import micKeyLenghtException


class TkipMicGenerator:
	'''
	Classe TkipMicGenerator

	Calcola il MIC con chiave K del messaggio in ingresso
	'''
	def __init__(self,mex,key):
		self.keyLenght = 8
		self.WordLength = 4
		self.mex = mex
		self.key = key


	def getMic(self):
		'''
		Ritorna il MIC associato al messaggio mex e alla chiave key
		'''
		# Separo la chiave da 64 bit in due parole da 32 bit
		k0,k1 = self.splitKeys()
		# Paddo il messaggio
		paddedMex = self.paddMex()
		#Calcolo N
		N = len(self.mex)

		# Comincio l'algoritmo
		[l,r] = [k0,k1]
		for i in range(0,N-1):
			# estraggo 4 byte dal messaggio paddato
			Mi = paddedMex[(4*i):(4*(i+1))]
			# faccio lo xor
			l = bool(l) ^ bool(Mi)
			# ricalcolo l e r
			[l,r] = self.b(l,r)
		return [str(l) + str(r)]


	def paddMex(self):
		'''
		Padda il messaggio in ingresso prima di calcolarne il MIC
		'''
		# Calcolo il resto della divisione modulo quattro della lunghezza di mex
		nWords,nToPadd = divmod(len(self.mex), self.WordLength)
		# Il numero di byte dev'essere aumentato di 4,5,6 o 7 byte di zeri
		# Quando si padda bisogna tenere conto che è già stato aggiunto ox5a
		paddedMex = self.mex + chr(0x5a) + chr(0)*(8-1-nToPadd)
		return paddedMex	


	def splitKeys(self):
		'''
		Splitta la chiave key nelle due chiavi k0 e k1 (interi a 32 bit)
		'''
		#print str(len(self.key))
		if (len(self.key) != self.keyLenght):
			raise micKeyLenghtException('len(key) != self.keyLenght','La lunghezza della chiave dev\'essere di 8 byte')
		k0,k1 = struct.unpack('<II', self.key)
		return (k0,k1)


	@classmethod
	def b(cls,l,r):
		'''
		effettua le operazioni della funzione b. Vedi pagina 171 della rfc
		'''
		r = r ^ (l << 17)		# r = r ^ (l << 17)
		l = (l + r) & 0xffffffffL	# l = (l+r) mod (2^32)  ---> prende i 32bit a destra
		r = r ^ cls.xswap(l)		# r = r ^ cls.xswap(l)
		l = (l + r) & 0xffffffffL
		r = r ^ (l << 3)		# r = r ^ (l << 3)
		l = (l + r) & 0xffffffffL
		r = r ^ (l >> 2)		# r = r ^ (l >> 2)
		l = (l + r) & 0xffffffffL
		return (l,r)


	@classmethod
	def xswap(cls,data):
		'''
		effettua lo swap dei due byte meno significativi del dato (big endian)
		'''
		# data è un intero positivo di 32bit big endian
		# devo swappare i due byte meno significativi che sono i due byte a sinistra
		# prendo il primo e il secondo byte della 
		primoByte = (data & 0xff000000)
		secondoByte = (data & 0x00ff0000)
		terzoEQuartoByte = (data & 0x0000ffff)
		swapped = (primoByte >> 8) + (secondoByte << 8) + terzoEQuartoByte
		return swapped

