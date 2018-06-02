#-*- coding: utf-8 -*-

'''
CORE de las librerías en python para realizar desinfectores de archivos
se escribirá con la librería lief, así se podrá acceder de forma sencilla
a las cabeceras y a algunas funciones interesantes

@author: Fare9
'''

import lief
import os,os.path
import sys
import tempfile

from lief import parse
from lief import is_pe,is_elf,is_macho

from DataTypes import PE_File
from Constants import ORIGIN,CURRENT,END
from Constants import SECTION_ALIGNMENT,FILE_ALIGNMENT



def getFileBinary(path):
    '''
    Función que devuelve los tipos de objetos diferentes
    según el tipo de archivo
    '''
    if os.path.isfile(path):
        if is_pe(path):
            return PE_File(path)
        else:
            raise Exception('ERROR happens at getFileBinary in Core.py. This is not a valid type of file')
        '''
        TO_DO
        elif is_elf(path):
            return ELF_File(path)
        elif is_macho(path):
            return MACHO_File(path)
        '''
    else:
        raise Exception('ERROR happens at getFileBinary in Core.py. This is not a valid path')

