#/usr/bin/python
# -*- coding: utf-8 -*-

'''

'''

import sys
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src/utilities')
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src/common_utility')
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src/crypto')
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src/packetStruct')
sys.path.append('/media/DATA/06-WorkSpace/netsec_wp/src')

# Set log level to benefit from Scapy warnings
import logging
logging.getLogger("scapy").setLevel(1)

from scapy.all import *
from wpa_struct_for_scapy import *
from packet_printer import stringInHex



def getEapolKeyPart(packet):
	'''
	ritorna il layer wpa_key del pacchetto passato in ingresso
	'''
	eap_pack = packet[EAPOL]
	eapol_key_pack = eap_pack[EAPOL_Key]
	wpa_key = eapol_key_pack[EAPOL_WPAKey]
	return wpa_key

def checkIsFirstPacket(packet):
	'''
	ritorna 
	'''



#definisco le variabili principali
path = '../pacchetti-catturati/'
mex = "Pairwise key expansion"
fourWayHandshakeMsg1Name = path + 'four_way_1'
fourWayHandshakeMsg2Name = path + 'four_way_2'
fourWayHandshakeMsg3Name = path + 'four_way_3'
fourWayHandshakeMsg4Name = path + 'four_way_4'
groupKeyHandshakeMsg1Name = path + 'group_key_1'
groupKeyHandshakeMsg2Name = path + 'group_key_2'
pms = 'H6x&@!1uLQ*()!12c0x\\f^\'?|s<SNgh-'


#leggo i quattro pacchetti
# rdpcap torna una lista e quindi devo prendere il primo elemento
p1 = rdpcap(fourWayHandshakeMsg1Name)[0] 
p2 = rdpcap(fourWayHandshakeMsg2Name)[0]
p3 = rdpcap(fourWayHandshakeMsg3Name)[0]
p4 = rdpcap(fourWayHandshakeMsg4Name)[0]


# prendo la parte eapol dei pacchetti
p1eapolKey = getEapolKeyPart(p1)
p2eapolKey = getEapolKeyPart(p2)
p3eapolKey = getEapolKeyPart(p3)
p4eapolKey = getEapolKeyPart(p4)


print '   KEY NONCE = ' + stringInHex(wpa_key.Nonce)






















