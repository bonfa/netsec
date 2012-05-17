#/usr/bin/python
# -*- coding: utf-8 -*-
'''
Questo modulo implementa i metodi base di crittografia come le funzioni prf e L
(pag 198 rfc)
'''
import sys
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src/common_utility')
#sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src/crypto')
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src/packetStruct')
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src')
#import hashlib
import hmac



def prf_384(key,a,b):
	'''
	Calcola la prf a 384 bit con chiave key di un messaggio formato dalle parti a,b e ritorna il risultato
	'''
	return prf(key,a,b,384)


def prf_512(key,a,b):
	'''
	Calcola la prf a 512 bit con chiave key di un messaggio formato dalle parti a,b e ritorna il risultato
	'''
	return prf(key,a,b,512)


def prf(key,a,b,length):
	'''
	Calcola la prf di lunghezza L con chiave key di un messaggio formato dalle parti a,b e ritorna il risultato
	'''
	r = ''
	for i in range(0,(length+159)/160):
		r = r + hSha1(key,a,b,i)
	return left(r,0,length)


def hSha1(key,a,b,i):
	'''
	Effettua l'hmac-sha1 con chiave k del messaggio (a+b+i)
	'''
	message = a + str(0b00000000) + b + str(i)
	m = hmac.new(key,message)
	return m.digest()


def left(data,F,L):
	'''
	Ritorna la parte sinistra di data, a partire da F fino a F+L-1
	'''
	return data[F:(F+L)]

