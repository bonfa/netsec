#/usr/bin/python
# -*- coding: utf-8 -*-
'''
pag 198 rfc
'''
import hashlib
import hmac



def prf_384(key,a,b):
	prf(k,a,b,384)


def prf_512(key,a,b):
	prf(k,a,b,512)


def prf(key,a,b,length):
	for i in range(0,(length+159)/160):
		r = r + hSha1(key,a,b,i)
	return left(r,0,length)


def hSha1(key,a,b,i):
	message = a + 0b00000000 + b + i
	m = hmac.new(key,message,hashlib.sha1())
	return m.digest()


def left(data,F,L):
	return data[F:F+L]






'''
cose che vanno da un'altra parte:

def prf_384(pmk,"Pairwise key expansion",AA,SPA,ANonce,SNonce):

def orderPadding(AA,SPA,ANonce,SNonce):
	minAddress = min(AA,SPA)
	maxAddress = max(AA,SPA)
	minNonce = min(ANonce,SNonce)
	maxNonce = max(ANonce,SNonce)
	return (minAddress,maxAddress,minNonce,maxNonce)

def curtailPmk(pmk,start,end):
	return left(pmk,start,end)

(minAddress,maxAddress,minNonce,maxNonce) = orderPadding(AA,SPA,ANonce,SNonce)
	if len(pmk) > 256:
		pmk = curtailPmk(pmk)
'''
