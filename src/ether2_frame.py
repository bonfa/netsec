#/usr/bin/python
# -*- coding: utf-8 -*-
"""
Contiene le classi che rappresentano i frame ethernet
"""


class EthernetIIFrame:
	"""
	Classe ethernet_II_frame

	Questa classe rappresenta il frame ethernet II.
	Il pacchetto è composto da:
		header
		payload

	L'header è contenuto nella classe ethernet_II_header.
	Il payload, invece, è rappresentato dal pacchetto eapol contenuto nel file eapol_pack.py
	"""


	def __init__(self, header, payload):
		"""
		Costruttore del pacchetto EAPOL:
		riceve in ingresso header e payload e li salva nelle apposite variabili.
		"""
		self.header = header
		self.payload = payload

	
	
	def to_string(self):
		"""
		Ritorna una stringa con i valori di tutti i campi del pacchetto in ordine:
		I valori sono separati da uno spazio
		"""
		return self.header.to_string() + ' ' + self.payload.to_string()




class EthernetIIHeader:
	"""
	Classe ethernet_II_header

	Questa classe rappresenta un header ethernet II.
	I campi presenti nell'header sono i seguenti:
		preamble: [8 byte] 
		dst_address: [6 byte]
		src_address: [6 byte]
		ethernet_type: [2 byte]
		-----
		  payload 
         	-----
		padding: [Variable, stuffs data field up to 46 bytes] 
		Frame Check Sequence: [4 bytes]
	"""


	
	def __init__(self, preamble, destination_address, source_address, ether_type, padding, frame_check_sequence):
		"""
		Contruttore dell'header ETHERNET II:
		riceve in ingresso i valori dei campi e li salva nelle apposite variabili.
		"""
		self.preamble = preamble
		self.destination_address = destination_address
		self.source_address = source_address
		self.ether_type = ether_type
		self.padding = padding
		self.frame_check_sequence = frame_check_sequence
 	
	
	def to_string(self):
		"""
		Ritorna una stringa con i valori dell'header in ordine, separati da uno spazio.
		"""
		head_str = str(self.preamble) + ' '
		head_str = head_str + str(self.destination_address) + ' '
		head_str = head_str + str(self.source_address) + ' '
		head_str = head_str + str(self.ether_type) + ' '
		head_str = head_str + str(self.padding) + ' '
		head_str = head_str + str(self.frame_check_sequence)
		return head_str










