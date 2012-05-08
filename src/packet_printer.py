#/usr/bin/python
# -*- coding: utf-8 -*-

"""
Stampa i pacchetti
"""
from eapol_pack import EapolPacket,EapolHeader,EapolPayload,EapolKeyInformationField,EapolKeyDataField,KdeFormatKeyDataField,GtkFormatKeyDataField
from ether2_frame import EthernetIIFrame,EthernetIIHeader
import socket
import struct


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
	print '   KEY REPLAY COUNTER = ' + str((struct.unpack('Q',eapolPayload.key_replay_counter)[0]))
	#print '   KEY NONCE = ' + 					eapolPayload.key_nonce
	#print '   EAPOL KEY IV = ' + 					eapolPayload.eapol_key_iv
	print '   KEY RSC = ' + str((struct.unpack('Q',eapolPayload.key_rsc)[0]))
	print '   RESERVED = ' + str((struct.unpack('Q',eapolPayload.reserved)[0]))
	#print '   KEY MIC = ' + eapolPayload.key_mic
	print '   KEY DATA LENGTH = ' + str(socket.ntohs(struct.unpack('H',eapolPayload.key_data_length)[0]))
	#printEapolKeyData(eapolPayload.key_data)	

def printEapolKeyInformationField(KeyInformationField):
	indent = '   '
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


