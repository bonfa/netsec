#/usr/bin/python
# -*- coding: utf-8 -*-

import subprocess
import sys

path = '../pacchetti-catturati/wwwlan_01/'
NomePacchetto1_4Way = path + 'four_way_1.pcap'
NomePacchetto2_4Way = path + 'four_way_2.pcap'
NomePacchetto3_4Way = path + 'four_way_3.pcap'
NomePacchetto4_4Way = path + 'four_way_4.pcap'
nomePacchettoDati = path + 'dataOnly.pcap'
#nomePacchettoDati = path + 'fish0all.pcap'	

pms = 'H6x&@!1uLQ*()!12c0x\\f^\'?|s<SNgh-'
ssid = 'WWWLAN'


# Eseguo PlateDetector sull'immagine
wpaDecryptor = subprocess.Popen([sys.executable,"./main.py",pms,ssid,NomePacchetto1_4Way,NomePacchetto2_4Way,NomePacchetto3_4Way,NomePacchetto4_4Way,nomePacchettoDati],stdout=None, stderr=None) 
decriptorStatus = wpaDecryptor.communicate()
