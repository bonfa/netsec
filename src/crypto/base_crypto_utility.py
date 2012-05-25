#/usr/bin/python
# -*- coding: utf-8 -*-
'''
Questo modulo implementa i metodi base di crittografia come le funzioni prf e L
(pag 198 e pag 1127 della rfc)
'''
import sys
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src/common_utility')
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src/packetStruct')
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src')
import hmac
import hashlib
import struct
import array
from math import ceil

'''
La lunghezza dei campi è in byte e non in bit.
La prf è fatta in modo tale che i byte da 0 a N contengano l'output della prf.

Input length [byte(bit)]=  16 (128 bit), 24 (192 bit), 32 (256 bit), 48 (384 bit), 64 (512 bit)

'''


def prf_384(key,prefix,data):
	'''
	Calcola la prf a 384 bit con chiave key di un messaggio formato dalle parti prefix,data e ritorna il risultato
	'''
	return prf(key,prefix,data,48)


def prf_512(key,prefix,data):
	'''
	Calcola la prf a 512 bit con chiave key di un messaggio formato dalle parti prefix,data e ritorna il risultato
	'''
	return prf(key,prefix,data,64)


def prf(key,prefix,data,length):
	'''
	Calcola la prf di lunghezza L con chiave key di un messaggio formato dalle parti prefix,data e ritorna il risultato
	'''
	r = ''
	for i in range(0,(length+19)/20):
		r = r + hSha1(key,prefix,data,i)
	return left(r,0,length)


def hSha1(key,prefix,data,i):
	'''
	Effettua l'hmac-sha1 con chiave k del messaggio (prefix+data+i)
	'''
	message = prefix + chr(0b00000000) + data + chr(i)
	m = hmac.new(key,message,hashlib.sha1)
	return m.digest()


def left(data,F,L):
	'''
	Ritorna la parte sinistra di data, a partire da F fino a F+L-1
	'''
	if F<0:
		raise ValueError('F can\'t be negative')
	if F+L>len(data):
		raise ValueError('F+L exceeds the vector dimension')
	return data[F:(F+L)]



def pbkdf2(passphrase,ssid,c,dkLen=32):
	'''
	Mappa passphrase e ssid di una wlan in una psk.
	Funziona solo per dkLen = 32
	'''
	hLen = 20
	numBlocks = ceil(float(dkLen)/float(hLen))
	r = dkLen - (numBlocks - 1)*hLen
	psk = ''
	for i in range(1,int(numBlocks)+1):
		psk += f(passphrase,ssid,c,i)
	return psk[0:dkLen]	

		
def f(passphrase,salt,c,it):
	'''
	funzione di base per la pbkdf2
	'''
	# Controlla che la codifica ASCII dei caratteri sia <126 e >32
	for i in range(0,len(passphrase)):
		if ord(passphrase[i])<32 or ord(passphrase[i])>126:
			raise ValueError('Character \'' + passphrase[i] +'[' + ord(passphrase[i])+']'+ '\' must be in range [32,126]')
	
	# Calcolo U1
	## trasformo il counter in unsigned integer a 32 bit big endian
	counterStr = struct.pack('>L',int(it));
	# creo la stringa di cui si calcola la prf
	inputString = salt + counterStr
	#print inputString.encode('hex')
	# calcolo la prf
	digestMaker = hmac.new(passphrase,inputString,hashlib.sha1)
	Ui = digestMaker.digest()
	output = Ui

	# Calcolo gli altri Ui
	for i in range(1,c):
		# Ui = prf(passphrase,Ui-1)
		digestMaker = hmac.new(passphrase,Ui,hashlib.sha1)
		Ui = digestMaker.digest()
		# output = output ^ Ui
		output = strXor(output,Ui) 
	# ritorno il risultato degli xor
	return output



def strXor(str1,str2):
	'''
	effettua lo xor tra due stringhe della stessa lunghezza
	'''
	if len(str1) != len(str2):
		raise ValueError('str1 and str2 must be of the same length')
	arr1 = array.array('B',str1)
	arr2 = array.array('B',str2)
	
	for i in range(len(arr1)):
		arr1[i] = arr1[i] ^ arr2[i]
	#arr1.reverse()
	return arr1.tostring()
