#/usr/bin/python
# -*- coding: utf-8 -*-
'''
Contiene delle operazioni di base che non sono implementate in python ma che potrebbero essere utili
'''

def leftRotationOperation(value,shift,bits=32):
	'''
	Effettua lo shift circolare a sinistra dei bit di value. Il numero di bit dello shift è definito dal parametro shift.
	bits indica il numero di bit che costituiscono il numero
	'''
	# Controllo che shift sia >= 0
	
	if (shift < 0):
		raise NegativeShiftValueException('shift < 0','shift value must be not negative')
	# Controllo che shift sia minore di bits altrimenti a shift sostituisco (shift mod bits)
	if (shift >= bits):
		shift = divmod(shift,bits)[1]
	return rightRotationOperation(value, bits - shift, bits)	
	



def rightRotationOperation(value,shift,bits=32):
	'''
	Effettua lo shift circolare a destra dei bit di value. Il numero di bit dello shift è definito dal parametro shift.
	bits indica il numero di bit che costituiscono il numero
	'''
	# Controllo che shift sia >= 0
	if (shift < 0):
		raise NegativeShiftValueException('shift < 0','shift value must be not negative')
	# Controllo che shift sia minore di bits altrimenti a shift sostituisco (shift mod bits)
	if (shift >= bits):
		shift = divmod(shift,bits)[1]
	# Creo la maschera di bit che seleziona gli 'shift' bit a destra
	mask = (2L**shift) - 1
	# Da 'value' estraggo i bit applicando la maschera
	maskBits = value & mask
	# La rotazione a destra si ottiene shiftando 'value' a destra di 'shift' posizioni e mettendo in OR con 'maskBits' shiftato di (bits-shift) posizioni a sinistra
	return (value >> shift) | (maskBits << (bits - shift))



def low8(num):
	'''
	ritorna il byte meno significativo di num
	'''
	return num & 0xff



def high8(num):
	'''
	ritorna num senza il byte meno significativo
	'''
	return num >> 8




def mk16(x,y):
		'''
		Prende due valori a 8 bit e ne ritorna uno a 16 bit
		x diventa il byte più significativo nel valore a 16 bit
		'''
		sixteenBitValue =  ((x << 8) + y) & 0xffff
		return sixteenBitValue


	
class NegativeShiftValueException(Exception):
	"""Eccezione chiamata quando il valore dello shift passato come parametro nelle operazioni di rotazione è negativo

	Attributes:
	expr -- input expression in which the error occurred
	msg  -- explanation of the error
	"""
	def __init__(self, expr, msg):
		self.expr = expr
		self.msg = msg	


