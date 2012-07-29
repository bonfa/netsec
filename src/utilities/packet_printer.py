#/usr/bin/python
# -*- coding: utf-8 -*-

"""
Stampa i pacchetti
"""
import sys
sys.path.append('../common_utility')
sys.path.append('../crypto')
sys.path.append('../packetStruct')
#sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src')
import socket
import struct


indent = '   '


def macAddressToString(addressInBit):
	return ':'.join('%02x' % ord(b) for b in addressInBit)


def etherTypeToString(addressInBit):
	return ''.join('%02x' % ord(b) for b in addressInBit)
	

def printEthernetHeader(ethernetHeader):
	print 'ETHERNET HEADER'
	print '   PREAMBLE = ' + str(ethernetHeader.preamble)
	print '   DESTINATION ADDRESS = ' + macAddressToString(ethernetHeader.destination_address)
	print '   SOURCE ADDRESS = ' + macAddressToString(ethernetHeader.source_address)
	print '   ETHER TYPE = 0x' + etherTypeToString(ethernetHeader.ether_type)
	print '   PADDING = ' + str(ethernetHeader.padding)
	print '   FCS = ' + str(ethernetHeader.frame_check_sequence)


def printEapolHeader(eapolHeader):
	print 'EAPOL HEADER'
	print '   PROTOCOL VERSION = ' + str(ord(eapolHeader.protocol_version))
	print '   PACKET TYPE = ' + str(ord(eapolHeader.packet_type))
	print '   PACKET BODY LENGTH = ' + str(socket.ntohs(struct.unpack('H',eapolHeader.body_length)[0]))


def printEapolPayload(eapolPayload):
	print 'EAPOL PAYLOAD'
	print '   DESCRYPTOR TYPE = ' + str(ord(eapolPayload.descriptor_type))
	printEapolKeyInformationField(eapolPayload.key_information)
	print '   KEY LENGTH = ' + str(socket.ntohs(struct.unpack('H',eapolPayload.key_length)[0]))
	print '   KEY REPLAY COUNTER = ' + str((struct.unpack('>Q',eapolPayload.key_replay_counter)[0]))
	print '   KEY NONCE = ' + stringInHex(eapolPayload.key_nonce)
	print '   EAPOL KEY IV = ' + stringInHex(eapolPayload.eapol_key_iv)
	print '   KEY RSC = ' + str((struct.unpack('>Q',eapolPayload.key_rsc)[0]))
	print '   RESERVED = ' + str((struct.unpack('>Q',eapolPayload.reserved)[0]))
	print '   KEY MIC = ' + stringInHex(eapolPayload.key_mic)
	print '   KEY DATA LENGTH = ' + str(socket.ntohs(struct.unpack('H',eapolPayload.key_data_length)[0]))
	if socket.ntohs(struct.unpack('H',eapolPayload.key_data_length)[0]) != 0:
		printEapolKeyData(eapolPayload.key_data)
	else:
		print '   KEY DATA = 0'


def printEapolKeyInformationField(KeyInformationField):
	print indent + 'KEY INFORMATION'
	print 2*indent + 'key_descriptor_version = ' + str(KeyInformationField.key_descriptor_version)
	print 2*indent + 'key_type = ' + str(KeyInformationField.key_type)
	print 2*indent + 'reserved = ' + str(KeyInformationField.reserved)
	print 2*indent + 'install = ' + str(KeyInformationField.install)
	print 2*indent + 'key_ack = ' + str(KeyInformationField.key_ack)
	print 2*indent + 'key_mic = ' + str(KeyInformationField.key_mic)
	print 2*indent + 'secure = ' + str(KeyInformationField.secure)
	print 2*indent + 'error = ' + str(KeyInformationField.error)
	print 2*indent + 'request = ' + str(KeyInformationField.request)
	print 2*indent + 'encrypted_key_data = ' + str(KeyInformationField.encrypted_key_data)
	print 2*indent + 'smk_message = ' + str(KeyInformationField.smk_message)
	print 2*indent + 'reserved_2 = ' + str(KeyInformationField.reserved_2)


def stringInHex(value):
	string = ''
	for b in value:
		string = string + str(hex(ord(b))).replace('0x',' ')
	return string
	

def printEapolKeyData(keyDataField):
	print indent + 'KEY DATA'
	print 2*indent + 'type = ' + str(ord(keyDataField.typ))
	print 2*indent + 'length = ' + str(ord(keyDataField.length))
	print 2*indent + 'OUI = ' + stringInHex(keyDataField.oui)
	print 2*indent + 'data type = ' + str(ord(keyDataField.data_type))
	printEapolKeyDataNoHeader(keyDataField.data)

	
def printEapolKeyDataNoHeader(data):
	print 2*indent + 'data = ' + stringInHex(data)

