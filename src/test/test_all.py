#/usr/bin/python
# -*- coding: utf-8 -*-
'''
Testa tutte le operazioni
'''

import unittest


if __name__ == '__main__':
	start_dir = '/media/DATA/06-WorkSpace/netsec_wp/src/test/'
	suite = unittest.TestLoader().discover(start_dir)	
	unittest.TextTestRunner(verbosity=2).run(suite)
