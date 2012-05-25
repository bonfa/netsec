#/usr/bin/python
# -*- coding: utf-8 -*-

class Error(Exception):
	"""Base class for exceptions in this module."""
	pass

class packetKindNotManaged(Error):
	"""Exception raised when in input there is a packet which is not eapol.

	Attributes:
	expr -- input expression in which the error occurred
	msg  -- explanation of the error
	"""

	def __init__(self, expr, msg):
		self.expr = expr
		self.msg = msg

class noPacketRead(Error):
	"""Exception raised when the pcap module doesn't find packet in input.

	Attributes:
		expr -- input expression in which the error occurred
		msg  -- explanation of the error
	"""
	def __init__(self, expr, msg):
		self.expr = expr
		self.msg = msg

class pmkTooShortException(Error):
	"""Exception raised when the pcap module doesn't find packet in input.

	Attributes:
		expr -- input expression in which the error occurred
		msg  -- explanation of the error
	"""
	def __init__(self, expr, msg):
		self.expr = expr
		self.msg = msg


class micKeyLenghtException(Error):
	"""Exception raised when the lenght of the tkip mic is not 8 bytes

	Attributes:
		expr -- input expression in which the error occurred
		msg  -- explanation of the error
	"""
	def __init__(self, expr, msg):
		self.expr = expr
		self.msg = msg


class MacNotSupportedException(Error):
	"""Exception raised when the lenght of the tkip mic is not 8 bytes

	Attributes:
		expr -- input expression in which the error occurred
		msg  -- explanation of the error
	"""
	def __init__(self, expr, msg):
		self.expr = expr
		self.msg = msg

class InputError(Error):
	"""Exception raised when the some input value doesn't respect some constraints

	Attributes:
		expr -- input expression in which the error occurred
		msg  -- explanation of the error
	"""
	def __init__(self, expr, msg):
		self.expr = expr
		self.msg = msg
