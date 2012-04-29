#/usr/bin/python
# -*- coding: utf-8 -*-



class eapol_packet:
	"""
	Classe eapol_packet

	Questa classe rappresenta un pacchetto EAPOL.
	Il pacchetto è composto da:
		header
		payload
	"""


	"""
	Costruttore del pacchetto EAPOL:
	riceve in ingresso header e payload e li salva nelle apposite variabili.
	"""
	def __init__(header,payload):
		self.header = header
		self.payload = payload

	
	"""
	Ritorna una stringa con i valori di tutti i campi del pacchetto in ordine:
	I valori sono separati da uno spazio
	"""
	def toString():
		return self.header.toString() + ' ' + self.payload.toString()




class eapol_header:
	"""
	Classe eapol_header

	Questa classe rappresenta un header EAPOL.
	I campi presenti nell'header sono i seguenti:
		protocol_version: [1 byte] 
		packet_type: [1 byte]
		body_length: [2 byte]
	"""


	"""
	Contruttore dell'header EAPOL:
	riceve in ingresso i valori dei tre campi e li salva nelle apposite variabili.
	"""
	def __init__(protocol_version, packet_type,body_length):
		self.protocol_version = protocol_version
		self.packet_type = packet_type
		self.body_length = body_length

 	
	"""
	Ritorna una stringa con i tre valori dell'header in ordine, separati da uno spazio.
	"""
	def toString():
		head_str = str(self.protocol_version) + ' '
		head_str = head_str + str(self.packet_type) + ' '
		head_str = head_str + str(self.body_length)
		return head_str




class eapol_payload:
	"""
	Classe eapol_payload

	Questa classe rappresenta il payload di un pacchetto EAPOL.
	I campi presenti nel payload sono i seguenti:
		descriptor_type: [1 byte]
		key_information: [2 byte]
		key_length: [8 byte]
		key_replay_counter: [32 byte]
		key_nonce: [16 byte]
		eapol_key_iv: [8 byte]
		key_rsc: [8 byte]
		reserved: [8 byte]
		key_mic: [16 byte]
		key_data_length: [2 byte]
		key_data: 
	"""


	"""
	Contruttore del payload EAPOL:
	riceve in ingresso i valori dei campi e li salva nelle apposite variabili.
	"""
	def __init__(descriptor_type,key_information, key_length, key_replay_counter, key_nonce, eapol_key_iv, key_rsc, reserved, key_mic, key_data_length, key_data):
		self.descriptor_type = descriptor_type
		self.key_information = key_information
		self.key_length = key_length
		self.key_replay_counter = key_replay_counter
		self.key_nonce = key_nonce
		self.eapol_key_iv = eapol_key_iv
		self.key_rsc = key_rsc
 		self.reserved = reserved
		self.key_mic = key_mic
		self.key_data_length = key_data_length
		self.key_data = key_data

	"""
	Ritorna una stringa con i valori  del payload in ordine:
	I valori sono separati da uno spazio
	"""
	def toString():
		payload_str = '' + str(self.descriptor_type) + ' '
		payload_str = payload_str + self.key_information.toString() + ' '
		payload_str = payload_str + str(self.key_length) + ' '
		payload_str = payload_str + str(self.key_replay_counter) + ' '
		payload_str = payload_str + str(self.key_nonce) + ' '
		payload_str = payload_str + str(self.eapol_key_iv) + ' '
		payload_str = payload_str + str(self.key_rsc) + ' '
		payload_str = payload_str + str(self.reserved) + ' '
		payload_str = payload_str + str(self.key_mic) + ' '
		payload_str = payload_str + str(self.key_data_length) + ' '
		payload_str = payload_str + str(self.key_data) + ' '
		return payload_str



class eapol_key_information_field:
	"""
	Classe eapol_key_information_field

	Questa classe rappresenta il campo Key Information di un pacchetto eapol.
	I sotto-campi presenti in questo campo sono i seguenti:
		key_descriptor_version: [3 bit]
		key_type: [1 bit]
		reserved: [2 bit]
		install: [1 bit] 
		key_ack: [1 bit]
		key_mic: [1 bit]
		secure: [1 bit]
		error: [1 bit]
		request: [1 bit] 
		encrypted_key_data: [1 bit]
		smk_message: [1 bit]
		reserved: [2 bit]
	"""
	

	"""
	Contruttore del campo key_information del pacchetto EAPOL:
	riceve in ingresso i valori dei campi e li salva nelle apposite variabili.
	"""	
	def __init__(key_descriptor_version,key_type,reserved,install,key_ack,key_mic,secure,error,request,encrypted_key_data,smk_message,reserved_2):
		self.key_descriptor_version = key_descriptor_version
		self.key_type = key_type
		self.reserved = reserved
		self.install = install
		self.key_ack = key_ack
		self.key_mic = key_mic
		self.secure = secure
		self.error = error
		self.request = request
		self.encrypted_key_data = encrypted_key_data
		self.smk_message = smk_message
		self.reserved_2 = reserved_2


	"""
	Ritorna una stringa con i valori dei sotto-campi in ordine separati da uno spazio.
	"""
	def toString():
		key_information_string = ''
		key_information_string = key_information_string + self.key_descriptor_version + ' '
		key_information_string = key_information_string + self.key_type + ' '
		key_information_string = key_information_string + self.reserved + ' '
		key_information_string = key_information_string + self.install + ' '
		key_information_string = key_information_string + self.key_ack + ' '
		key_information_string = key_information_string + self.key_mic + ' '
		key_information_string = key_information_string + self.secure + ' '
		key_information_string = key_information_string + self.error + ' '
		key_information_string = key_information_string + self.request + ' '
		key_information_string = key_information_string + self.encrypted_key_data + ' '
		key_information_string = key_information_string + self.smk_message + ' '
		key_information_string = key_information_string + self.reserved_2 + ' '
		return key_information_string
		



class eapol_key_data_field:
	"""
	Classe eapol_key_data_field

	Questa classe rappresenta il campo KEY_DATA di un pacchetto eapol.
	Il campo data viene trattato in modo generico nel caso il campo non si di tipo kde 
	(questo perchè ai fini dell'elaborato non dovrebbe essere importante)
	"""

	"""
	Costruttore:
	riceve i dati e li imposta nel campo data
	"""	
	def __init__(data):
		self.data = data

	"""
	Ritorna una stringa con i dati contenuti nel campo KEY_DATA
	"""
	def toString():
		return str(self.data)




class kde_format_key_data_field(eapol_key_data_field):
	"""
	Classe kde_format_key_data_field 

	@extend: eapol_key_data_field
	Questa classe rappresenta il campo KEY_DATA di un pacchetto eapol nel formato KDE
	I sotto-campi presenti in questo campo sono i seguenti:
		type: [1 byte]
		length: [1 byte]
		oui: [3 byte]
		data_type: [1 byte]
		data: [length-4 byte]
	"""


	"""
	Contruttore:
	riceve in ingresso i valori dei campi e li salva nelle apposite variabili.
	"""
	def __init__(typ,length,oui,data_type,data):
		self.typ = typ
		self.length = length
		self.oui = oui
		self.data_type = data_type
		self.data = data


	"""
	Ritorna una stringa con i dati contenuti nel campo KEY_DATA nel formato KDE
	"""
	def toString():
		key_data_string = ''
		key_data_string = key_data_string + str(self.typ) + ' '
		key_data_string = key_data_string + str(self.length) + ' '
		key_data_string = key_data_string + str(self.oui) + ' '
		key_data_string = key_data_string + str(self.data_type) + ' '
		key_data_string = key_data_string + str(self.data) + ' '
		return key_data_string



class gtk_format_key_data_field():
	"""
	Classe gtk_format_key_data_field 

	Questa classe rappresenta il campo KEY_DATA.DATA di un pacchetto eapol nel caso GTK KDE
	I sotto-campi presenti in questo campo sono i seguenti:
	KeyID: [2 bit]
	tx: [2 bit]
	reserved: [4 bit]
	gtk: [(length-6) byte]
	"""


	"""
	Contruttore:
	riceve in ingresso i valori dei campi e li salva nelle apposite variabili.
	"""
	def __init__(keyID,tx,reserved,gtk):
		self.keyID = keyID
		self.tx = tx
		self.reserved = reserved
		self.gtk = gtk

	"""
	Ritorna una stringa con i dati contenuti nel campo ordinati separati da uno spazio
	"""
	def toString():
		data_field_str = ''
		data_field_str = data_field_str + self.keyID + ' '
		data_field_str = data_field_str + self.tx + ' '
		data_field_str = data_field_str + self.reserved + ' '
		data_field_str = data_field_str + self.gtk + ' '
