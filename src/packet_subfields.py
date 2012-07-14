#/usr/bin/python
# -*- coding: utf-8 -*-

'''
Ritorna i sottopacchetti dei pacchetti
Utilizza le propiretà di scapy
'''

from scapy.all import *
from wpa_struct_for_scapy import *



def getEapolKeyPart(packet):
	'''
	ritorna il layer wpa_key del pacchetto passato in ingresso
	'''
	eap_pack = packet[EAPOL]
	eapol_key_pack = eap_pack[EAPOL_Key]
	wpa_key = eapol_key_pack[EAPOL_WPAKey]
	return wpa_key	



def getPairwiseFlag(packet):
	'''
	ritorna il flag pairwise del campo KeyInfo del pacchetto passato in ingresso
	'''
	return (packet.KeyInfo >> 3) & 1



def getInstallFlag(packet):
	'''
	ritorna il flag install del campo KeyInfo del pacchetto passato in ingresso
	'''
	return (packet.KeyInfo >> 6) & 1



def getAckFlag(packet):
	'''
	ritorna il flag ack del campo KeyInfo del pacchetto passato in ingresso
	'''
	return (packet.KeyInfo >> 7) & 1



def getMicFlag(packet):
	'''
	ritorna il flag mic del campo KeyInfo del pacchetto passato in ingresso
	'''
	return (packet.KeyInfo >> 8) & 1



def getSecureFlag(packet):
	'''
	ritorna il flag secure del campo KeyInfo del pacchetto passato in ingresso
	'''
	return (packet.KeyInfo >> 9) & 1





