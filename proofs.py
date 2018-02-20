#-*- coding: utf-8 -*-
'''
    Desinfector para el virus Padme
'''
from Core import *
from DataTypes import *
from Constants import *


_debug = True

if __name__ == '__main__':

    binario = getFileBinary("strings_modified.exe")

    ep_binario = getBinaryRVAEntryPoint(binario)

    print "RVA Entry Point: 0x%x" % (ep_binario)

    buffer_ = ""

    RVA_Seek(binario,ep_binario,ORIGIN)

    buffer_ = RVA_Read(binario,4)

    print "First bytes of binary: 0x%x" % (buffer_)

    killBinary(binario)