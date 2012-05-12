#/usr/bin/python
# -*- coding: utf-8 -*-
'''
Questo modulo implementa i metodi di crittografia usati dal 4 way handshake
'''

import base_crypto_utility
from exception import pmkTooShortException
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
			self.pmk = self.curtailPmk(pmk,0,255)
		elif len(pmk) < 32:
			raise pmkTooShortException('len(pmk) < 256','pmk is too short')
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
		kek = base_crypto_utility.left(prf,0,8);
		kck = base_crypto_utility.left(prf,8,8);
		tk = base_crypto_utility.left(prf,16,16);
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


