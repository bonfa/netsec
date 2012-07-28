#/usr/bin/python
# -*- coding: utf-8 -*-

import subprocess
import sys

path = '../pacchetti-catturati/ultimo/'
NomePacchetto1_4Way = path + 'four_way_1'
NomePacchetto2_4Way = path + 'four_way_2'
NomePacchetto3_4Way = path + 'four_way_3'
NomePacchetto4_4Way = path + 'four_way_4'
nomePacchettoDati = path + 'dataOnly'

pms = 'H6x&@!1uLQ*()!12c0x\\f^\'?|s<SNgh-'
ssid = 'WWWLAN'
#authenticatorAddressTuple = (0x00,0x18,0xe7,0x45,0x0e,0x22)		
#supplicantAddressTuple = (0x00,0x19,0xd2,0x4a,0x39,0xb8)


# Eseguo PlateDetector sull'immagine
wpaDecryptor = subprocess.Popen([sys.executable,"./main.py",pms,ssid,NomePacchetto1_4Way,NomePacchetto2_4Way,NomePacchetto3_4Way,NomePacchetto4_4Way,nomePacchettoDati],stdout=None, stderr=None) 
decriptorStatus = wpaDecryptor.communicate()
print decriptorStatus
