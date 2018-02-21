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


'''
    Funciones para obtener valores del PE
'''
def getBinaryRVAEntryPoint(binary_):
    '''
    Método para obtener el RVA entry point de un archivo,
    este será el RVA en memoria, no en disco, por tanto,
    será necesario si queremos movernos aquí, el obtener
    el offset del RVA
    '''

    if binary_.type == 'PE_File':    # si es del tipo PE_File
        return binary_.getRVAEntryPoint()

def getBinarySectionAlignment(binary_):
    '''
    Método para obtener el section alignment de un archivo
    '''
    if binary_.type == 'PE_File':
        return binary_.getSectionAlignment()

def getBinaryFileAlignment(binary_):
    '''
    Método para obtener el file alignment de un archivo
    '''
    if binary_.type == 'PE_File':
        return binary_.getFileAlignment()

def getBinaryImageBase(binary_):
    '''
    Método para obtener la imagen base según la cabecera
    del binario
    '''
    if binary_.type == 'PE_File':
        return binary_.getImageBase()

'''
    Funciones para modificar valores del PE
'''
def setBinaryRVAEntryPoint(binary_,new_rva):
    '''
    Función para modificar el entry point en la cabecera
    '''
    binary_.setRVAEntryPoint(new_rva)

'''
    Funciones para alinear valores
'''
def alignSizeOfCode(binary_,type_of_alignment,virus_size):
    '''
    Método para quitar de size of code el virus_size y la
    alineación
    TODO: hacerlo super genérico para todos los campos de tamaño
    '''
    if binary_.type == 'PE_File':
        if type_of_alignment == SECTION_ALIGNMENT:
            x = binary_.getSizeOfCode() - virus_size
            rest = x % binary_.getSectionAlignment()
            original_size = x - rest
            binary_.setSizeOfCode(original_size)

        elif type_of_alignment == FILE_ALIGNMENT:
            x = binary_.getSizeOfCode() - virus_size
            rest = x % binary_.getFileAlignment()
            original_size = x - rest
            binary_.setSizeOfCode(original_size)


'''
    Funciones para poderse mover, escribir
    y leer del binario
'''
def RVA_Seek(binary_,rva,seek_type):
    '''
    Método para moverse a través del binario a base de 
    RVAs, en disco será necesario moverse por offsets
    la clase hará el trabajo del cambio
    '''
    if ( (seek_type != ORIGIN) and (seek_type != CURRENT) and (seek_type != END)):
        raise Exception("Method of seek_type not supported")

    if binary_.type == 'PE_File':
        return binary_.move_file_rva(rva,seek_type)

def RVA_Read(binary_,size_):
    '''
    Método para leer del binario, admitirá un buffer y 
    un tamaño a leer
    '''
    if binary_.type == 'PE_File':
        return binary_.read_file_rva(size_)

def RVA_Write(binary_,buffer_):
    '''
    Método para escribir en el binario, admite un buffer
    de tamaño que sea.
    '''
    if binary_.type == 'PE_File':
        binary_.write_file_rva(buffer_)


'''
    Utilidades varias para el binario
'''
def checkBinarySign(binary_,sign):
    '''
    Función para checkear en un binario la firma de un virus
    en el campo win32 version value
    '''
    if binary_.type == 'PE_File':
        return binary_.checkSign(sign)

def putOutPegote(binary_,rva,size):
    '''
    Método para quitar de un archivo el tamaño indicado por
    size a partir del RVA dado
    '''
    f = tempfile.NamedTemporaryFile(delete=False)

    file_size = binary_.file_size

    from_ = binary_.get_offset_from_rva(rva)

    to_ = binary_.get_offset_from_rva(rva+size)

    RVA_Seek(binary_,0,ORIGIN)

    for i in range(file_size):

        if (i>= from_) and (i<to_):
            byte = RVA_Read(binary_,1)
            continue

        byte = RVA_Read(binary_,1)

        f.write(chr(byte))

    killBinary(binary_) # paramos el handle

    f.close()

    os.remove(binary_.path)

    os.rename(f.name,binary_.path)

    binary_.start_binary()

    binary_.start_handle()

def cleanSign(binary_):
    '''
    Método para quitar la firma de un virus del campo de la cabecera
    win32_version_value
    '''
    binary_.cleanSign()
'''
    Función para acabar con el objeto
'''
def killBinary(binary_):
    '''
    Método para finalizar el binario
    '''
    binary_.stop_handle()

