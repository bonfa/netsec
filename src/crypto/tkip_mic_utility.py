#/usr/bin/python
# -*- coding: utf-8 -*-
'''
Contiene le utility necessarie a effettuare il MIC del 4 way handshake
'''
import sys
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src/common_utility')
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src/packetStruct')
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src/utilities')
import struct
from exception import micKeyLenghtException
from base_operations import leftRotationOperation,rightRotationOperation,NegativeShiftValueException



class TkipMicGenerator:
	'''
	Classe TkipMicGenerator

	Calcola il MIC con chiave K del messaggio in ingresso
	mex e key sono stringhe
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
		N = len(paddedMex)/4

		# Comincio l'algoritmo
		[l,r] = [k0,k1]
		for i in range(0,N):
			# estraggo 4 byte dal messaggio paddato
			Mi = struct.unpack('<I',paddedMex[(4*i):(4*(i+1))])[0]
			# faccio lo xor
			l = l ^ Mi
			# ricalcolo l e r
			[l,r] = self.b(l,r)
		#print len(l) + ' ' + len(r)
		mic = struct.pack('<II',l,r)		
		return mic


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
			raise micKeyLenghtException('len(key) != self.keyLenght',"La lunghezza della chiave dev'essere di 8 byte")
		k0,k1 = struct.unpack('<II', self.key)
		return (k0,k1)


	@classmethod
	def b(cls,l,r):
		'''
		Effettua le operazioni della funzione b. 
		Le operazioni effettuate sono le seguenti (pag 171 della rfc):
		.) <<< = rotazione verso sinistra (non shift)
		.) >>> = rotazione verso sinistra (non shift)
		.) ^ = xor
		.) a mod b: prendo i b bit di a, a partire da destra
		'''
		r = r ^ leftRotationOperation(l,17)		# r = r ^ (l <<< 17)
		l = (l + r) & 0xffffffffL			# l = (l+r) mod (2^32)  ---> prende i 32bit a destra
		r = r ^ cls.xswap(l)				# r = r ^ cls.xswap(l)
		l = (l + r) & 0xffffffffL
		r = r ^ leftRotationOperation(l,3)		# r = r ^ (l <<< 3)
		l = (l + r) & 0xffffffffL
		r = r ^ rightRotationOperation(l,2)		# r = r ^ (l >>> 2)
		l = (l + r) & 0xffffffffL
		return (l,r)


	@classmethod
	def xswap(cls,data):
		'''
		effettua lo swap dei due byte meno significativi e dei due byte più significativi del dato (little endian)
		xswap(ABCD) = BADC
		'''
		# data è un intero positivo di 32bit little endian		
		primoTerzoByte = (data & 0xff00ff00)
		secondoQuartoByte = (data & 0x00ff00ff)
		swapped = (primoTerzoByte >> 8) | (secondoQuartoByte << 8)
		return swapped

