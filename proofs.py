#-*- coding: utf-8 -*-
'''
    Desinfector para el virus Padme
'''
from Core import *
from DataTypes import *
from Constants import *
from Utilities import *


_debug = True


# Constantes del PADME



def get_delta_offset(binary_):
	'''
	'''
	rva_ep_binario = getBinaryRVAEntryPoint(binary_)

	base_address = getBinaryImageBase(binary_)

	ep_binario = rva_ep_binario + base_address

	first_address = ep_binario + 8

	RVA_Seek(binary_,rva_ep_binario + 0xC,ORIGIN)

	second_address = RVA_Read(binary_,4)

	second_address = swapBytes(second_address)

	delta_offset = first_address - second_address

	if _debug:
		print "RVA ep_binario: 0x%x" % (rva_ep_binario)

		print "Binary base address: 0x%x" % (base_address)

		print "First address: 0x%x" % (first_address)

		print "Second address: 0x%x" % (second_address)

		print "Delta offset: 0x%x" % (delta_offset)

	return delta_offset



if __name__ == '__main__':

    binario = getFileBinary("strings_modified.exe")

    get_delta_offset(binario)

    buffer_ = ""

    ep_binario = getBinaryRVAEntryPoint(binario)

    RVA_Seek(binario,ep_binario,ORIGIN)

    buffer_ = RVA_Read(binario,4)

    print "First bytes of binary: 0x%x" % (buffer_)

    killBinary(binario)