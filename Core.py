#-*- coding: utf-8 -*-

'''
CORE of python libraries to do file disinfectors, we will use lief library
so will be easy to access headers and some interesting functions


@file: Core.py
@version: 0.1
@author: Fare9
'''


import lief
import os,os.path
import sys
import tempfile

from lief import parse
from lief import is_pe,is_elf,is_macho

from FileTypes.PEType import PE_File
from Utils.Constants import ORIGIN,CURRENT,END
from Utils.Constants import SECTION_ALIGNMENT,FILE_ALIGNMENT



def getFileBinary(path):
    '''
    Función que devuelve los tipos de objetos diferentes
    según el tipo de archivo
    '''
    if os.path.isfile(path):
        if is_pe(path):
            return PE_File(path)
        else:
            raise Exception('ERROR happened at getFileBinary in Core.py. This is not a valid type of file')
        '''
        TO_DO
        elif is_elf(path):
            return ELF_File(path)
        elif is_macho(path):
            return MACHO_File(path)
        '''
    else:
        raise Exception('ERROR happened at getFileBinary in Core.py. This is not a valid path')

