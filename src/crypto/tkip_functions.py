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
from base_operations import rightRotationOperation,low8,high8,mk16



class TKIPmixingFunction:
	'''
	Classe TKIPmixingFunction

	Implementazione della mixing function usata dal tkip per criptare
	tk,ta,tsc sono stringhe
	wepSeed è una tupla
	'''
	def __init__(self,tk,ta,tsc):
		self.tk = tk
		self.ta = ta
		self.tsc = tsc
		self.ttak = 0

	def getWepSeed(self):
		'''
		Ritorna il wep seed, risultato dell'elaborazione del tkip
		'''
		mixingFunctionPart1 = TKIPphaseOne(self.tk,self.ta,self.tsc)
		self.ttak = mixingFunctionPart1.getTTAK()
		mixingFunctionPart2 = TKIPphaseTwo(self.ttak,self.tk,self.tsc) 	
		return mixingFunctionPart2.getWEPSeed()



class TKIPphaseOne:
	'''
	Classe TKIPphaseOne

	Effettua la fase 1 della mixing function utilizzata durante la crittografia del tkip
	tk,ta,tsc sono stringhe	
	'''
	def __init__(self,tk,ta,tsc):
		self.tk = tk
		self.ta = ta
		self.tsc = tsc
		self.attributeSplitter = TKIPvariableSplitter(tk,ta,tsc)



	def getTTAK(self):
		'''
		calcola i ttak a partire da tk,ta e tsc. L'algoritmo è descritto a pagina 177 della rfc
		'''
		# prendo i valori di input separati in byte
		ta0,ta1,ta2,ta3,ta4,ta5 = self.attributeSplitter.getSplittedTA()
		tk0,tk1,tk2,tk3,tk4,tk5,tk6,tk7,tk8,tk9,tk10,tk11,tk12,tk13,tk14,tk15 = self.attributeSplitter.getSplittedTK()
		tk_tuple = (tk0,tk1,tk2,tk3,tk4,tk5,tk6,tk7,tk8,tk9,tk10,tk11,tk12,tk13,tk14,tk15)
		tsc0,tsc1,tsc2,tsc3,tsc4,tsc5 = self.attributeSplitter.getSplittedTSC()
		'''step_1'''
		# inizializzo i ttak
		ttak0 = mk16(tsc3,tsc2)
		ttak1 = mk16(tsc5,tsc4)
		ttak2 = mk16(ta1,ta0)
		ttak3 = mk16(ta3,ta2)
		ttak4 = mk16(ta5,ta4)
		'''step_2'''
		# mescolo i ttak
		for i in range(8):
			j = 2*(i & 1)
			# tutte le operazioni devono essere eseguite in modulo 2^16 per non andare out of bound
			ttak0 = (ttak0 + S(ttak4 ^ mk16(tk_tuple[1+j],tk_tuple[0+j]))) & 0xffff
			ttak1 = (ttak1 + S(ttak0 ^ mk16(tk_tuple[5+j],tk_tuple[4+j]))) & 0xffff
			ttak2 = (ttak2 + S(ttak1 ^ mk16(tk_tuple[9+j],tk_tuple[8+j]))) & 0xffff
			ttak3 = (ttak3 + S(ttak2 ^ mk16(tk_tuple[13+j],tk_tuple[12+j]))) & 0xffff
			ttak4 = (ttak4 + S(ttak3 ^ mk16(tk_tuple[1+j],tk_tuple[0+j]))) & 0xffff
			ttak4 = (ttak4 + i) & 0xffff
		# ritorno la tupla contenente i ttak
		return ttak0,ttak1,ttak2,ttak3,ttak4




class TKIPphaseTwo:
	'''
	Classe TKIPphaseTwo

	Effettua la fase 2 della mixing function utilizzata durante la crittografia del tkip
	ttak è una tupla
	tk,tsc sono stringhe
	wepSeed è una tupla	
	'''
	def __init__(self,ttak,tk,tsc):
		self.ttak = ttak
		self.tk = tk
		self.tsc = tsc	
		self.attributeSplitter = TKIPvariableSplitter(tk,0,tsc)

	
	def getWEPSeed(self):
		'''
		calcola il WEPSeed da ttak,tk e tsc. L'algoritmo è descritto a pagina 178 della rfc
		wepSeed è una tupla
		'''
		# prendo i valori di input separati in byte
		tk0,tk1,tk2,tk3,tk4,tk5,tk6,tk7,tk8,tk9,tk10,tk11,tk12,tk13,tk14,tk15 = self.attributeSplitter.getSplittedTK()
		tk_tuple = (tk0,tk1,tk2,tk3,tk4,tk5,tk6,tk7,tk8,tk9,tk10,tk11,tk12,tk13,tk14,tk15)
		tsc0,tsc1,tsc2,tsc3,tsc4,tsc5 = self.attributeSplitter.getSplittedTSC()
		# ttak è già una tupla e quindi non dev'essere splittato
		'''step_1'''
		ppk0 = self.ttak[0]
		ppk1 = self.ttak[1]
		ppk2 = self.ttak[2]
		ppk3 = self.ttak[3]
		ppk4 = self.ttak[4]
		ppk5 = (self.ttak[4] + mk16(tsc1,tsc0)) & 0xffff
		
		'''step_2'''
		ppk0 = (ppk0 + S(ppk5 ^ mk16(tk1,tk0))) & 0xffff
		ppk1 = (ppk1 + S(ppk0 ^ mk16(tk3,tk2))) & 0xffff
		ppk2 = (ppk2 + S(ppk1 ^ mk16(tk5,tk4))) & 0xffff
		ppk3 = (ppk3 + S(ppk2 ^ mk16(tk7,tk6))) & 0xffff
		ppk4 = (ppk4 + S(ppk3 ^ mk16(tk9,tk8))) & 0xffff
		ppk5 = (ppk5 + S(ppk4 ^ mk16(tk11,tk10))) & 0xffff
	
		ppk0 = (ppk0 + self.rotR1(ppk5 ^ mk16(tk13,tk12))) & 0xffff
		ppk1 = (ppk1 + self.rotR1(ppk0 ^ mk16(tk15,tk14))) & 0xffff
		ppk2 = (ppk2 + self.rotR1(ppk1)) & 0xffff
		ppk3 = (ppk3 + self.rotR1(ppk2)) & 0xffff
		ppk4 = (ppk4 + self.rotR1(ppk3)) & 0xffff
		ppk5 = (ppk5 + self.rotR1(ppk4)) & 0xffff
			
		ppk_tuple = (ppk0,ppk1,ppk2,ppk3,ppk4,ppk5)
		'''step3'''
		wepSeed=[]
		wepSeed.append(tsc1)
		wepSeed.append((tsc1 | 0x20) & 0x7F)
		wepSeed.append(tsc0)
		wepSeed.append(low8((ppk5 ^ mk16(tk1,tk0))>>1))
		
		#wepSeed_tuple = (wepSeed0,wepSeed1,wepSeed2,wepSeed3,wepSeed4,wepSeed5)
		for i in range(6):
			wepSeed.append(low8(ppk_tuple[i]))
			wepSeed.append(high8(ppk_tuple[i]))
	
		return tuple(wepSeed)
		

	@classmethod
	def rotR1(cls,value):
		'''
		Effettua la rotazione a destra di un bit del valore passato come parametro
		'''
		return rightRotationOperation(value,1,16)			

	


class TKIPvariableSplitter:
	'''
	Classe TKIPvariableSplitter

	Splitta le variabili da stringhe a tuple
	'''
	def __init__(self,tk,ta,tsc):
		self.tk = tk		
		self.ta = ta
		self.tsc = tsc
	
	

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

		
			





