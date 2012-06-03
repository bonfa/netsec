#/usr/bin/python
# -*- coding: utf-8 -*-
'''
Testa tutte le operazioni
'''

import unittest


if __name__ == '__main__':
	start_dir = './'
	suite = unittest.TestLoader().discover(start_dir)	
	unittest.TextTestRunner(verbosity=2).run(suite)
