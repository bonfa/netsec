#/usr/bin/python
# -*- coding: utf-8 -*-
'''
Questo modulo contiene la classe che si occupa di effettuare l'encryption RC4
'''

import sys
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src/common_utility')


class arcFour:
	'''
	classe arcFour - è un qualcosa di più del cipher rc4 vero e proprio.
	Questa classe riceve in input il seed e il dato in input e ritorna l'output
	'''
	

	def __init__(self,key):
		'''key è una tupla'''
		self.key = key
		#self.input = None
		self.i = None
		self.j = None
		self.SBox = self.setSBox()


	

	#def setInput(self,inputValue):
	#	'''
	#	Imposta l'input che dev'essere xorato con il keystream
	#	'''
	#	self.input = inputValue


	
	def setSBox(self):
		'''
		Genera le SBox a partire dalla chiave
		'''
		## Inizializzo i e j		
		self.i = 0
		self.j = 0
		## Inizializzo l'S-box
		S = range(256)
		
		## Creo S2 e lo riempio con la chiave
		keyRepetition,decimalPart = divmod(256,len(self.key))
		S2 = list(self.key)*keyRepetition
		S2 = S2 + list(self.key)[0:len(self.key)*decimalPart]

		## Inizializzazione dell'S-box
		j = 0
		for i in range(256):
			j = (j + S[i] + S2[i]) % 256
			temp = S[i]
			S[i] = S[j]
			S[j] = temp

		# Setto l'S-box
		self.S = S
		
	

	def getKeyStreamByte(self):
		'''
		Genera il KeyStream
		'''
		self.i = (self.i+1) % 256
		self.j = (self.j+ self.S[self.i]) % 256
		temp = self.S[self.i]
		self.S[self.i] = self.S[self.j]
		self.S[self.j] = temp
		t = (self.S[self.i]+self.S[self.j]) % 256
		k = self.S[t]
		return k



	#def getOutput(self):
	#	'''
	#	Ritorna l'output del cipher ottenuto facendo lo xor tra l'input e il keyStream
	#	'''
	#	output = []
	#	for i in range(len(self.input)):
	#		keyStreamByte = self.getKeyStreamByte()	
	#		outputBlock = self.input[i] ^ keyStreamByte
	#		output.append(outputBlock)
	#	return tuple(output)


