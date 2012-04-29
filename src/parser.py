#/usr/bin/python
# -*- coding: utf-8 -*-

import eapol_pack
import ether2_frame

class splitter:
	'''
	Classe splitter

	Questa classe prende un pacchetto, lo separa in header e payload e ne crea tutti i campi.
	'''
	EAPOL_TYPE = '\x88\x8e'
	ethernet_offset = 14



	'''
	Il costruttore dal pacchetto separa il campo header e il payload e ritorna un oggetto che contiene i due attributi (header e payload) che a loro 	 volta contengono tutte la variabili separate
	'''
	def __init__(frame):
		header = get_ethernet_header(frame)
		# passo l'array a partire dal primo byte del payload così non devo sommare l'offset ogni volta
		payload = get_ethernet_payload(frame[self.ethernet_offset:])
		
		self.ethernet_frame = ethernet_II_frame(frame,payload)



	'''
	Crea un oggetto di tipo ethernet header.

	I campi preamble, padding e fcs sono azzerati, tanto non servono.
	Gli offset sono in byte
	'''
	def get_ethernet_header(packet):
		# estraggo i campi dell'header e creo un oggetto che rappresenta l'header ethernet		
		preamble = 0
		dst_address = packet[0:6]
		src_address = packet[6:12]
		ether_type = packet[12:14]
		padding = 0
		fcs = 0
		
		header = ethernet_II_header(preamble,dst_address,src_address,ether_type,padding,fcs)
		return header



	'''
	Crea un oggetto di tipo ethernet payload.

	Funziona solo se il pacchetto è un pacchetto di tipo EAPOL
	'''
	def get_ethernet_payload(packet):
		if header.ether_type == self.EAPOL_TYPE: 
			payload = get_eapol_packet() 
			return payload
		else
			raise packetKindNotManaged('The content of the payload is not managed by the software')




	'''
	Crea un oggetto di tipo eapol_packet
	'''
	def get_eapol_packet(eapol_structure):
		header = get_eapol_header(eapol_structure)
		payload = get_eapol_payload(eapol_structure[4:],header.body_length)
		
		packet = eapol_packet(header,payload)
		return packet


		
	'''
	Crea un oggetto di tipo eapol_header a partire dal pacchetto eapol
	'''	
	def get_eapol_header(eapol_packet):
		protocol_version = eapol_packet[0:1]
		packet_type = eapol_packet[1:2]
		body_length = eapol_packet[2:4]
		return eapol_header(protocol_version,packet_type,body_length);
			


	'''
	Crea un oggetto di tipo eapol_payload a partire dal pacchetto eapol
	'''	
	def get_eapol_payload(eapol_payload_structure,payload_length):
		descriptor_type = eapol_payload_structure[0:1]
		key_information = get_key_information(eapol_payload_structure[1:3])
		key_length = eapol_payload_structure[3:5]
		key_replay_counter = eapol_payload_structure[5:13]
		key_nonce = eapol_payload_structure[13:45]
		eapol_key_iv = eapol_payload_structure[45:61]
		key_rsc = eapol_payload_structure[61:69]
		reserved = eapol_payload_structure[69:77]
		key_mic = eapol_payload_structure[77:93]
		key_data_length = eapol_payload_structure[93:95]
		key_data = get_eapol_key_data_field(eapol_payload_structure[95:],key_data_length,payload_length)
		
		return (eapol_payload(descriptor_type,key_information,key_length,key_replay_counter,key_nonce,eapol_key_iv,key_rsc,reserved,key_mic,key_data_length, key_data))



	'''
	Crea un oggetto di tipo key_information a partire dai due byte del pacchetto eapol che contengono questi campi
	'''	
	def get_key_information(key_info_structure):
		key_descriptor_version = key_info_structure[1] & 7
		key_type = key_info_structure[1] & 8
		reserved = 0
		install = key_info_structure[1] & 32
		key_ack = key_info_structure[1] & 64

		key_mic = key_info_structure[2] & 1
		secure = key_info_structure[2] & 2
		error = key_info_structure[2] & 4
		request = key_info_structure[2] & 8
		encrypted_key_data = key_info_structure[2] 16
		smk_message = key_info_structure[2] & 32
		reserved_2 = 0
		
		return (eapol_key_information_field(key_descriptor_version,key_type,reserved,install,key_ack,key_mic,secure,error,request,encrypted_key_data,smk_message,reserved_2))



	'''
	Crea un oggetto di tipo eapol_payload a partire dal pacchetto eapol
	
	Il campo viene trattato come se fosse sempre nel formato KDE (perchè ai fini dell'elaborato, serve solo questo)
	'''	
	def get_eapol_key_data_field(eapol_payload_structure):
		typ = eapol_payload_structure[0:1]
		length = eapol_payload_structure[1:2]
		oui = eapol_payload_structure[2:5]
		data_type = eapol_payload_structure[5:6]
		
		if (data_type == 1): #GTK KDE
			data = (eapol_payload_structure[6:6+length-4],length)
		else
			data = eapol_payload_structure[6:6+length-4]
		
		return kde_format_key_data_field(typ,length,oui,data_type,data)



	'''
	Crea un oggetto di tipo key_data di tipo gtk kde a partire dal campo data del pacchetto eapol
	
	Il campo viene trattato come se fosse sempre nel formato KDE (perchè ai fini dell'elaborato, serve solo questo)
	'''
	def get_eapol_key_data_field(gtk_structure,length):
		keyID = gtk_structure[0:1] & 3
		tx = gtk_structure[0:1] & 4
		reserved = gtk_structure[0:1] & 240 + gtk_structure[1:2]
		gtk = gtk_structure[2:length-6]
		
		return gtk_format_key_data_field(keyID,tx,reserved,gtk)		
		
		
	
	

