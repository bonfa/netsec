#/usr/bin/python
# -*- coding: utf-8 -*-
'''
Contiene le utility necessarie a effettuare la mixing function del tkip
'''
import sys
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src/common_utility')
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src/packetStruct')
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src')
import struct
from tkip_sboxes import S



class TKIPphaseOne:
	'''
	Classe TKIPphaseOne

	Effettua la fase 1 della mixing function utilizzata durante la crittografia del tkip
	'''
	def __init__(self,tk,ta,tsc):
		self.tk = tk
		self.ta = ta
		self.tsc = tsc



	def getTTAK(self):
		'''
		calcola i ttak a partire da tk,ta e tsc. L'algoritmo è descritto a pagina 177 della rfc
		'''
		# prendo i valori di input separati in byte
		ta0,ta1,ta2,ta3,ta4,ta5 = self.getSplittedTA()
		tk0,tk1,tk2,tk3,tk4,tk5,tk6,tk7,tk8,tk9,tk10,tk11,tk12,tk13,tk14,tk15 = self.getSplittedTK()
		tk_tuple = (tk0,tk1,tk2,tk3,tk4,tk5,tk6,tk7,tk8,tk9,tk10,tk11,tk12,tk13,tk14,tk15)
		tsc0,tsc1,tsc2,tsc3,tsc4,tsc5 = self.getSplittedTSC()
		'''step_1'''
		# inizializzo i ttak
		ttak0 = self.mk16(tsc3,tsc2)
		ttak1 = self.mk16(tsc5,tsc4)
		ttak2 = self.mk16(ta1,ta0)
		ttak3 = self.mk16(ta3,ta2)
		ttak4 = self.mk16(ta5,ta4)
		'''step_2'''
		# mescolo i ttak
		for i in range(8):
			j = 2*(i & 1)
			# tutte le operazioni devono essere eseguite in modulo 2^16 per non andare out of bound
			
			ttak0 = (ttak0 + S(ttak4 ^ self.mk16(tk_tuple[1+j],tk_tuple[0+j]))) & 0xffff
			ttak1 = (ttak1 + S(ttak0 ^ self.mk16(tk_tuple[5+j],tk_tuple[4+j]))) & 0xffff
			ttak2 = (ttak2 + S(ttak1 ^ self.mk16(tk_tuple[9+j],tk_tuple[8+j]))) & 0xffff
			ttak3 = (ttak3 + S(ttak2 ^ self.mk16(tk_tuple[13+j],tk_tuple[12+j]))) & 0xffff
			ttak4 = (ttak4 + S(ttak3 ^ self.mk16(tk_tuple[1+j],tk_tuple[0+j]))) & 0xffff
			ttak4 = (ttak4 + i) & 0xffff
		# ritorno la tupla contenente i ttak
		return ttak0,ttak1,ttak2,ttak3,ttak4



	def getSplittedTA(self):
		'''
		A partire dalla stringa che rappresenta l'indirizzo (TA), ritorna i singoli byte
		'''
		ta0 = ord(self.ta[0])
		ta1 = ord(self.ta[1])
		ta2 = ord(self.ta[2])
		ta3 = ord(self.ta[3])
		ta4 = ord(self.ta[4])	
		ta5 = ord(self.ta[5])
		return ta0,ta1,ta2,ta3,ta4,ta5
	


	def getSplittedTK(self):
		'''
		A partire dalla stringa che rappresenta la chiave (TK), ritorna i singoli byte
		'''
		tk0 = ord(self.tk[0])
		tk1 = ord(self.tk[1])
		tk2 = ord(self.tk[2])
		tk3 = ord(self.tk[3])
		tk4 = ord(self.tk[4])
		tk5 = ord(self.tk[5])
		tk6 = ord(self.tk[6])
		tk7 = ord(self.tk[7])
		tk8 = ord(self.tk[8])
		tk9 = ord(self.tk[9])
		tk10 = ord(self.tk[10])
		tk11 = ord(self.tk[11])
		tk12 = ord(self.tk[12])
		tk13 = ord(self.tk[13])
		tk14 = ord(self.tk[14])
		tk15 = ord(self.tk[15])		
		return tk0,tk1,tk2,tk3,tk4,tk5,tk6,tk7,tk8,tk9,tk10,tk11,tk12,tk13,tk14,tk15



	def getSplittedTSC(self):
		'''
		A partire dalla stringa che rappresenta la chiave (TK), ritorna i singoli byte
		'''
		tsc0 = ord(self.tsc[0])
		tsc1 = ord(self.tsc[1])
		tsc2 = ord(self.tsc[2])
		tsc3 = ord(self.tsc[3])
		tsc4 = ord(self.tsc[4])	
		tsc5 = ord(self.tsc[5])
		return tsc0,tsc1,tsc2,tsc3,tsc4,tsc5



	@classmethod
	def mk16(cls,x,y):
		'''
		Prende due valori a 8 bit e ne ritorna uno a 16 bit
		x diventa il byte più significativo nel valore a 16 bit
		'''
		sixteenBitValue =  ((x << 8) + y) & 0xffff
		return sixteenBitValue





class TKIPphaseTwo:
	'''
	Classe TKIPphaseTwo

	Effettua la fase 2 della mixing function utilizzata durante la crittografia del tkip
	'''
	def __init__(self,ttak,tk,tsc):
		self.ttak = ttak
		self.tk = tk
		self.tsc = tsc	


	
	def getWEPSeed(self):
		'''
		calcola il WEPSeed da ttak,tk e tsc. L'algoritmo è descritto a pagina 178 della rfc
		'''
		

