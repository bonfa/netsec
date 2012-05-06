#/usr/bin/python
# -*- coding: utf-8 -*-
"""
Contiene un po' di funzioni utili in fase di debug
"""

from eapol_pack import EapolPacket,EapolHeader,EapolPayload,EapolKeyInformationField,EapolKeyDataField,KdeFormatKeyDataField,GtkFormatKeyDataField
from ether2_frame import EthernetIIFrame,EthernetIIHeader
from exception import Error,packetKindNotManaged


def stampa_key_info_from_array(key_info_structure):
	print 'len =' + str(len(key_info_structure))
	print 'key = ' + bin(ord(key_info_structure[0]))+bin(ord(key_info_structure[1]))
	print 'key[0] = ' + bin(ord(key_info_structure[0]))
	print 'key[1] = ' +bin(ord(key_info_structure[1]))	


def stampa_key_info_field_per_field(key_info_structure):
	for i in range(0,8):	
		to_print = (ord(key_info_structure[1]) & (1 << i)) >> i
		print str(i) + ' ' + bin (to_print)


def stampa_key_info_from_my_object():
	print 'key_descriptor_version = ' + str(key_descriptor_version)
	print 'key_type = ' + str(key_type)
	print 'reserved = ' + str(reserved)
	print 'install = ' + str(install)
	print 'key_ack = ' + str(key_ack)
	print 'key_mic = ' + str(key_mic)
	print 'secure = ' + str(secure)
	print 'error = ' + str(error)
	print 'request = ' + str(request)
	print 'encrypted_key_data = ' + str(encrypted_key_data)
	print 'smk_message = ' + str(smk_message)
	print 'reserved_2 = ' + str(reserved_2)
