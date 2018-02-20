#-*- coding: utf-8 -*-

'''
Métodos de utilidad para usar con lecturas de memoria,
lectura de PEs, ELF...
'''

import struct
from struct import pack,unpack


def swapBytes(number):
	'''
	Pasa de Big-Endian a Little-Endian
	y vice versa.

	THANKS TO: @MZ_IAT
	'''
	return unpack('>L',pack("<L",number))[0]