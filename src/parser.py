#/usr/bin/python
# -*- coding: utf-8 -*-
"""
A partire dalla struttura che contiene i dati sniffati da wireshark crea dei nuovi oggetti
"""

from eapol_pack import EapolPacket,EapolHeader,EapolPayload,EapolKeyInformationField,EapolKeyDataField,KdeFormatKeyDataField,GtkFormatKeyDataField
from ether2_frame import EthernetIIFrame,EthernetIIHeader

class Splitter:
	'''
	Classe splitter

	Questa classe prende un pacchetto, lo separa in header e payload e ne crea tutti i campi.
	'''
	EAPOL_TYPE = '\x88\x8e'
	ethernet_offset = 14



	
	def __init__(self,frame):
		'''
		Il costruttore dal pacchetto separa il campo header e il payload e ritorna un oggetto che contiene i due attributi (header e payload) che a 			loro volta contengono tutte la variabili separate
		'''
		header = self.get_ethernet_header(frame)
		# passo l'array a partire dal primo byte del payload così non devo sommare l'offset ogni volta
		payload = self.get_ethernet_payload(frame[self.ethernet_offset:],header.ether_type)
		
		self.ethernet_frame = EthernetIIFrame(frame,payload)



	#@classmethod
	def get_ethernet_header(self,packet):
		'''
		Crea un oggetto di tipo ethernet header.

		I campi preamble, padding e fcs sono azzerati, tanto non servono.
		Gli offset sono in byte
		'''
		# estraggo i campi dell'header e creo un oggetto che rappresenta l'header ethernet		
		preamble = 0
		dst_address = packet[0:6]
		src_address = packet[6:12]
		ether_type = packet[12:14]
		padding = 0
		fcs = 0
		
		header = EthernetIIHeader(preamble,dst_address,src_address,ether_type,padding,fcs)
		return header



	
	def get_ethernet_payload(self,packet,ether_type):
		'''
		Crea un oggetto di tipo ethernet payload.

		Funziona solo se il pacchetto è un pacchetto di tipo EAPOL
		'''
		if ether_type == self.EAPOL_TYPE: 
			payload = self.get_eapol_packet(packet) 
			return payload
		else:
			raise packetKindNotManaged('The content of the payload is not managed by the software')




	
	def get_eapol_packet(self,eapol_structure):
		'''
		Crea un oggetto di tipo eapol_packet
		'''
		header = self.get_eapol_header(eapol_structure)
		payload = self.get_eapol_payload(eapol_structure[4:],header.body_length)
		
		packet = EapolPacket(header,payload)
		return packet


		
	#@classmethod	
	def get_eapol_header(self,eapol_packet):
		'''
		Crea un oggetto di tipo eapol_header a partire dal pacchetto eapol
		'''
		protocol_version = eapol_packet[0:1]
		packet_type = eapol_packet[1:2]
		body_length = eapol_packet[2:4]
		return EapolHeader(protocol_version,packet_type,body_length)
			


	#@classmethod	
	def get_eapol_payload(self,eapol_payload_structure,payload_length):
		'''
		Crea un oggetto di tipo eapol_payload a partire dal pacchetto eapol
		'''
		descriptor_type = eapol_payload_structure[0:1]
		key_information = self.get_key_information(eapol_payload_structure[1:3])
		key_length = eapol_payload_structure[3:5]
		key_replay_counter = eapol_payload_structure[5:13]
		key_nonce = eapol_payload_structure[13:45]
		eapol_key_iv = eapol_payload_structure[45:61]
		key_rsc = eapol_payload_structure[61:69]
		reserved = eapol_payload_structure[69:77]
		key_mic = eapol_payload_structure[77:93]
		key_data_length = eapol_payload_structure[93:95]
		key_data = self.get_eapol_key_data_field(eapol_payload_structure[95:95+key_data_length])
		
		return (EapolPayload(descriptor_type,key_information,key_length,key_replay_counter,key_nonce,eapol_key_iv,key_rsc,reserved,key_mic,key_data_length, key_data))



	#@classmethod	
	def get_key_information(self,key_info_structure):
		'''
		Crea un oggetto di tipo key_information a partire dai due byte del pacchetto eapol che contengono questi campi
		'''
		key_descriptor_version = key_info_structure[1] & 7
		key_type = key_info_structure[1] & 8
		reserved = 0
		install = key_info_structure[1] & 32
		key_ack = key_info_structure[1] & 64

		key_mic = key_info_structure[2] & 1
		secure = key_info_structure[2] & 2
		error = key_info_structure[2] & 4
		request = key_info_structure[2] & 8
		encrypted_key_data = key_info_structure[2] & 16
		smk_message = key_info_structure[2] & 32
		reserved_2 = 0
		
		return (EapolKeyInformationField(key_descriptor_version,key_type,reserved,install,key_ack,key_mic,secure,error,request,encrypted_key_data,smk_message,reserved_2))



		
	def get_eapol_key_data_field(self,eapol_payload_structure):
		'''
		Crea un oggetto di tipo eapol_payload a partire dal pacchetto eapol
		
		Il campo viene trattato come se fosse sempre nel formato KDE (perchè ai fini dell'elaborato, serve solo questo)
		'''
		typ = eapol_payload_structure[0:1]
		length = eapol_payload_structure[1:2]
		oui = eapol_payload_structure[2:5]
		data_type = eapol_payload_structure[5:6]
		
		if (data_type == 1): #GTK KDE
			data = self.get_eapol_key_gtk_field(eapol_payload_structure[6:6+length-4],length)
		else:
			data = eapol_payload_structure[6:6+length-4]
		
		return KdeFormatKeyDataField(typ,length,oui,data_type,data)



	
	def get_eapol_key_gtk_field(self,gtk_structure,length):
		'''
		Crea un oggetto di tipo key_data di tipo gtk kde a partire dal campo data del pacchetto eapol
		
		Il campo viene trattato come se fosse sempre nel formato KDE (perchè ai fini dell'elaborato, serve solo questo)
		'''
		keyID = gtk_structure[0:1] & 3
		tx = gtk_structure[0:1] & 4
		reserved = gtk_structure[0:1] & 240 + gtk_structure[1:2]
		gtk = gtk_structure[2:length-6]
		
		return GtkFormatKeyDataField(keyID,tx,reserved,gtk)		
		
		
	
	

