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


def pbkdf2(passphrase,ssid,ssidLen,c,dkLen):
	'''
	Mappa passphrase e ssid in una psk.
	'''
	l,r = divmod()	
	
	
