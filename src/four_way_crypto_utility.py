#/usr/bin/python
# -*- coding: utf-8 -*-
'''
Questo modulo implementa i metodi di crittografia usati dal 4 way handshake
'''

import base_crypto_utility
from exception import pmkTooShortException,micKeyLenghtException
from 
#"Pairwise key expansion"


class cryptographyManager:
	'''
	Classe crpytographyManager

	Contiene i metodi di crittografia chiamati durante le operazioni del 4 way handshake
	'''
	
	def __init__(self,pmk,mex,AA,SPA,ANonce,SNonce,length):
		'''
		Imposta i dati necessari al cryptographyManager:
		PMK è la chiave. Se la pmk è più lunga di 256 bit, viene troncata.
		I valori AA,SPA,ANonce,SNonce sono i campi fondamentali che costituiranno il messaggio di cui calcolare l'hash
		Length è la lunghezza del risultato della prf
		'''
		if len(pmk) > 32:
			self.pmk = self.curtailPmk(pmk,0,32)
		elif len(pmk) < 32:
			raise pmkTooShortException('len(pmk) < 32','pmk is too short')
		else:
			self.pmk = pmk
		self.mex = mex
		self.AA = AA
		self.SPA = SPA
		self.ANonce = ANonce
		self.SNonce = SNonce
		self.length = length


	def prf(self):
		'''
		effettua la prf 
		'''
		(minAddress,maxAddress,minNonce,maxNonce) = self.orderPadding()
		variablePart = minAddress + maxAddress + minNonce + maxNonce
		return base_crypto_utility.prf_512(self.pmk,self.mex,variablePart)


	def getKeys(self):
		'''
		ottiene la prf, da essa estrae le tre chiavi KEK,KCK,TK e ritorna una tupla che contiene le tre chiavi nel seguente ordine [KEK,KCK,TK]
		'''
		prf = self.prf()
		kek = base_crypto_utility.left(prf,0,16);
		kck = base_crypto_utility.left(prf,16,16);
		tk = base_crypto_utility.left(prf,32,32);
		return [kek,kck,tk]
		

	def orderPadding(self):
		'''
		Ritorna la tupla ordinata che rappresenta il messaggio
		'''
		minAddress = min(self.AA,self.SPA)
		maxAddress = max(self.AA,self.SPA)
		minNonce = min(self.ANonce,self.SNonce)
		maxNonce = max(self.ANonce,self.SNonce)
		return (minAddress,maxAddress,minNonce,maxNonce)	


	@classmethod
	def curtailPmk(cls,pmk,start,end):
		'''
		Se la pmk è troppo lunga, la seleziona tra start e start+end
		'''
		return base_crypto_utility.left(pmk,start,end)






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


	def getMic():
		'''
		Ritorna il MIC associato al messaggio mex e alla chiave key
		'''
		# Separo la chiave da 64 bit in due parole da 32 bit
		[k0,k1] = self.splitKeys()
		# Paddo il messaggio
		paddedMex = paddMex()
		#Calcolo N
		N = len(self.mex)

		# Comincio l'algoritmo
		[l,r] = [k0,k1]
		for i in range(0,N-1):
			l = l ^ (M-i)
			[l,r] = b(l,r)
		return [l,r]


	def paddMex():
		'''
		Padda il messaggio in ingresso prima di calcolarne il MIC
		'''
		# Calcolo il resto della divisione modulo quattro della lunghezza di mex
		nWords,nToPadd = divmod(len(self.mex), self.WordLength)
		# Il numero di byte dev'essere aumentato di 4,5,6 o 7 byte di zeri
		# Quando si padda bisogna tenere conto che è già stato aggiunto ox5a
		paddedMex = self.mex + chr(0x5a) + chr(0)*(8-1-nToPadd)
		return paddedMex	


	def splitKeys():
		'''
		Splitta la chiave key nelle due chiavi k0 e k1 (interi a 32 bit)
		'''
		if (len(key) != self.keyLenght)
			raise micKeyLenghtException('len(key) != self.keyLenght','La lunghezza della chiave dev\'essere di 8 byte')
		k0,k1 = self._key = unpack('<II', self.key)
		return ko,k1


	def b():




