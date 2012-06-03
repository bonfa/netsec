#/usr/bin/python
# -*- coding: utf-8 -*-
'''
script che riceve in input una stringa e aggiunge i caratteri 0x in ingresso e i caratteri ,0x in posizione ogni due caratteri. Viene usato per splittare una stringa di valori esadecimali in una tupla
'''
import sys

a = sys.argv[1]
a = a.replace("\n","")
a_l = list(a)

a_l.insert(0,'0x')
k = 3
print(a_l)
while k < len(a_l):
	a_l.insert(k,',0x')	
	k += 3

print "".join(a_l)
