#/usr/bin/python
# -*- coding: utf-8 -*-
"""
A partire dalla struttura che contiene i dati sniffati da wireshark crea dei nuovi oggetti.
Per il momento funziona solo per i pacchetti ethernet II e eapol.
I dati vengono salvati così come sono, come insiemi di bit. Non vengono interpretati in interi o altro, (a parte i bit del campo key information del pacchetto eapol)
"""

from eapol_pack import EapolPacket,EapolHeader,EapolPayload,EapolKeyInformationField,EapolKeyDataField,KdeFormatKeyDataField,GtkFormatKeyDataField
from ether2_frame import EthernetIIFrame,EthernetIIHeader
from exception import Error,packetKindNotManaged
import my_debug
import packet_printer
import socket
import struct


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
		#print '1.1'
		header = self.get_ethernet_header(frame)
		packet_printer.printEthernetHeader(header)
		#print '1.2'
		# passo l'array a partire dal primo byte del payload così non devo sommare l'offset ogni volta
		payload = self.get_ethernet_payload(frame[self.ethernet_offset:],header.ether_type)
		#print '1.3'
		self.ethernet_frame = EthernetIIFrame(frame,payload)
		#self.numero = self.numero + 1
		#print '---[' + str(self.numero) + ']---'
		#print '1.4'


	
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
		#print '2.1'
		if ether_type == self.EAPOL_TYPE: 
			#print '2.2'
			payload = self.get_eapol_packet(packet) 
			#print '2.3'
			return payload
		else:
			#print '2.2'
			raise packetKindNotManaged('The content of the payload is not managed by the software')




	
	def get_eapol_packet(self,eapol_structure):
		'''
		Crea un oggetto di tipo eapol_packet
		'''
		#print '3.1'
		header = self.get_eapol_header(eapol_structure)
		packet_printer.printEapolHeader(header)
		#print '3.2'
		payload = self.get_eapol_payload(eapol_structure[4:],header.body_length)
		packet_printer.printEapolPayload(payload)
		#print '3.3'
		packet = EapolPacket(header,payload)
		#print '3.4'
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
		#print '4.1'
		descriptor_type = eapol_payload_structure[0:1]
		#print '4.2'
		key_information = self.get_key_information(eapol_payload_structure[1:3])
		#print '4.3'
		key_length = eapol_payload_structure[3:5]
		key_replay_counter = eapol_payload_structure[5:13]
		key_nonce = eapol_payload_structure[13:45]
		eapol_key_iv = eapol_payload_structure[45:61]
		key_rsc = eapol_payload_structure[61:69]
		reserved = eapol_payload_structure[69:77]
		key_mic = eapol_payload_structure[77:93]
		key_data_length = eapol_payload_structure[93:95]
		#print '4.4'
		#print (ord(descriptor_type))
		#print key_information
		#key_data
		#print ' ' + str(socket.ntohs(struct.unpack('H',key_data_length)[0]))
		if (socket.ntohs(struct.unpack('H',key_data_length)[0])) > 0:
			#print 'c'
			key_data = self.get_eapol_key_data_field(eapol_payload_structure[95:])
		else: 
			#print 'd'
			key_data = 0
		#print '4.5'
		return EapolPayload(descriptor_type,key_information,key_length,key_replay_counter,key_nonce,eapol_key_iv,key_rsc,reserved,key_mic,key_data_length, key_data)



	#@classmethod	
	def get_key_information(self,key_info_structure):
		'''
		Crea un oggetto di tipo key_information a partire dai due byte del pacchetto eapol che contengono questi campi
		
		Questo metodo separa la struttura nei due byte e ne legge i singoli campi. 
		Di seguito c'è un breve riassunto dei flag e della loro posizione nella struttura (che è quella dalla rfc letta da dx)
		
		---------------------------------------------------------------------------------------------------------------------------------------
		|	   |  SMK  |  Encrypted |	    |		|	   |	   ||   	|	  |	     |  key	|    key     |	
		| reserved |  mex  |    Key	|  Request  | 	Error	|  Secure  |  Key  ||  Key Ack	| Install | Reserved |  type	| descriptor |
		|	   |	   |	Data	|	    |		|      	   |  MIC  ||  	 	|	  |	     |	        |  version   |
		---------------------------------------------------------------------------------------------------------------------------------------
		   b0-1	      b2         b3          b4          b5 	     b6        b7        b8         b9       b10-11      b12        b13-15
		'''
		#print '5.1'
		#my_debug.stampa_key_info_from_array(key_info_structure)
		#my_debug.stampa_key_info_field_per_field(key_info_structure)

		key_descriptor_version = ord(key_info_structure[1:2]) & 0b00000111
		key_type = (ord(key_info_structure[1:2]) & 0b00001000) >> 3
		reserved = 0
		install = (ord(key_info_structure[1:2]) & 0b01000000) >> 6
		key_ack = (ord(key_info_structure[1:2]) & 0b10000000) >> 7

		key_mic = (ord(key_info_structure[0:1]) & 0b00000001)
		secure = (ord(key_info_structure[0:1]) &  0b00000010) >> 1
		error = (ord(key_info_structure[0:1]) & 0b00000100) >> 2
		request = (ord(key_info_structure[0:1]) & 0b00001000) >> 3
		encrypted_key_data = (ord(key_info_structure[0:1]) & 0b00010000) >> 4
		smk_message = (ord(key_info_structure[0:1]) & 0b00100000) >> 5
		reserved_2 = 0

		#print '5.2'
		return (EapolKeyInformationField(key_descriptor_version,key_type,reserved,install,key_ack,key_mic,secure,error,request,encrypted_key_data,smk_message,reserved_2))



		
	def get_eapol_key_data_field(self,eapol_payload_structure):
		'''
		Crea un oggetto di tipo eapol_payload a partire dal pacchetto eapol
		
		Il campo viene trattato come se fosse sempre nel formato KDE (perchè ai fini dell'elaborato, serve solo questo)
		'''
		#print '6.1'
		print ' ' + str(len(eapol_payload_structure))
		typ = eapol_payload_structure[0:1]
		length = eapol_payload_structure[1:2]
		oui = eapol_payload_structure[2:5]
		data_type = eapol_payload_structure[5:6]
		
		#print '6.2'
		print (ord(data_type))
		if (ord(data_type) == 1): #GTK KDE
			#print '6.3.a'
			data = self.get_eapol_key_gtk_field(eapol_payload_structure[6:6+length-4],length)
			#print '6.4.a'
		else:
			#print '6.3.b'
			#print ' ' + str(len(length))
			data = eapol_payload_structure[6:(6+ord(length)-4)]
			#print '6.4.b'
		
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
		
		
	
	

