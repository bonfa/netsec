#/usr/bin/python
# -*- coding: utf-8 -*-

import subprocess
import sys

path = '../pacchetti-catturati/nicola_02/'
NomePacchetto1_4Way = path + 'four_way_1.pcap'
NomePacchetto2_4Way = path + 'four_way_2.pcap'
NomePacchetto3_4Way = path + 'four_way_3.pcap'
NomePacchetto4_4Way = path + 'four_way_4.pcap'
nomePacchettoDati = path + 'wpa-psk-iPhone.pcap'

pms = 'BaX\'vN66pr'
ssid = 'NicolaZ_Net'

# Eseguo PlateDetector sull'immagine
wpaDecryptor = subprocess.Popen([sys.executable,"./main.py",pms,ssid,NomePacchetto1_4Way,NomePacchetto2_4Way,NomePacchetto3_4Way,NomePacchetto4_4Way,nomePacchettoDati,'True'],stdout=None, stderr=None) 
decriptorStatus = wpaDecryptor.communicate()
