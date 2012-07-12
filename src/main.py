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


#leggo il primo pacchetto
p1 = rdpcap(fourWayHandshakeMsg1Name) # è una lista
p2 = rdpcap(fourWayHandshakeMsg2Name)
p3 = rdpcap(fourWayHandshakeMsg3Name)
p4 = rdpcap(fourWayHandshakeMsg4Name)

#print ls(EAPOL_Key)
#print ls(EAPOL_WPAKey)
#print ls(EAPOL)

#  Ether / EAPOL KEY / EAPOL_Key / EAPOL_WPAKey
eap_pack = p1[0][EAPOL]
eapol_key_pack = eap_pack[EAPOL_Key]
wpa_key = eapol_key_pack[EAPOL_WPAKey]

#wpa_key.sprintf(r"%EAPOL_WPAKey.WPAKeyMIC%")
print '   KEY NONCE = ' + stringInHex(wpa_key.Nonce)






















