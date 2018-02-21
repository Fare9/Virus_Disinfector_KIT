#-*- coding: utf-8 -*-

'''
Tipos de archivos soportados, estos tendrán clases
para manejar handles y tipos binarios de lief

@author: Fare9
'''

import lief
import os,os.path
import sys
import binascii

from lief import parse
from lief import is_pe,is_elf,is_macho

from Constants import ORIGIN,CURRENT,END



class PE_File():
    '''
    Clase para manejar los archivos del tipo PE, 
    estos contendrán un handle para poder usarlo 
    como archivo de apertura/escritura/lectura/cierre
    y además contendrán un objeto de tipo binary
    de la librería lief
    '''
    def __init__(self,path):
        self.path = path
        self.file_size = os.path.getsize(self.path)
        self.handle = None
        self.binary_ = None
        self.type = 'PE_File'

        self.start_binary()
        self.start_handle()

    def start_binary(self):
        '''
        Método para arrancar el binario de lief con el path ofrecido
        para el objeto.
        '''
        self.binary_ = parse(self.path)

    def start_handle(self):
        '''
        Método para arrancar el handle del archivo.
        '''
        try:
            self.handle = open(self.path,'r+b')
        except Exception as e:
            raise type(e)(e.message + ' happens at start_handle in Core.py')

    def stop_handle(self):
        '''
        Método para finalizar el handle, y acabar
        con todo
        '''
        self.handle.close()

    def get_offset_from_rva(self,rva):
        '''
        Método para obtener el offset del archivo, 
        según un RVA
        '''
        offset = self.binary_.rva_to_offset(rva)
        return offset

    def move_file_rva(self,rva,seek_type):
        '''
        Método para mover el puntero del archivo,
        para moverlo tomaremos un RVA del archivo
        en memoria, y haremos un seek desde el sitio
        dado por el usuario
        '''
        try:
            offset_to_move = self.binary_.rva_to_offset(rva)
            self.handle.seek(offset_to_move,seek_type)
        except Exception as e:
            raise type(e)(e.message + ' happens at move_file_rva in Core.py')

    def read_file_rva(self,number_of_bytes):
        '''
        Método para leer del archivo. Antes se ha 
        podido mover, a través de move_file_rva
        '''
        try:
            buffer_ = self.handle.read(number_of_bytes)
            buffer_ = int(binascii.hexlify(buffer_),16)
            return buffer_
        except Exception as e:
            raise type(e)(e.message + ' happens at read_file_rva in Core.py')

    def write_file_rva(self,buffer_):
        '''
        Método para escribir en el archivo. Antes se ha
        podido mover, a través de move_file_rva
        '''
        try:
            self.handle.write(buffer_)
        except Exception as e:
            raise type(e)(e.message + ' happens at write_file_rva in Core.py')

    def getRVAEntryPoint(self):
        '''
        Método para obtener el RVA de un EP de un PE
        '''
        op_header = self.binary_.optional_header

        return op_header.addressof_entrypoint

    def setRVAEntryPoint(self,rva):
        '''
        Método para establecer el RVA del archivo.
        Paramos el handle, y lo volvemos abrir, para 
        que se recargue en disco

        :param dword rva: RVA a establecer del archivo
        '''   

        pointer_position = self.handle.tell()

        self.stop_handle()

        op_header = self.binary_.optional_header

        op_header.addressof_entrypoint = rva

        self.binary_.write(self.path)

        self.start_handle()

        self.handle.seek(pointer_position,ORIGIN)

    def getSizeOfCode(self):
        '''
        Método para obtener el Size of code del bianrio
        '''
        op_header = self.binary_.optional_header

        return op_header.sizeof_code

    def setSizeOfCode(self,value):
        '''
        Método para establecer el nuevo valor de size of code
        '''
        pointer_position = self.handle.tell()

        self.stop_handle()

        op_header = self.binary_.optional_header

        op_header.sizeof_code = value

        self.binary_.write(self.path)

        self.start_handle()

        self.handle.seek(pointer_position,ORIGIN)

    def checkSign(self,value):
        '''
        Método para checkear si un archivo está firmado
        por algún tipo de virus con algún valor.

        :param dword value: firma del virus
        '''
        op_header = self.binary_.optional_header

        return op_header.win32_version_value == value

    def cleanSign(self):
        '''
        Método para quitar la firma de un virus, y dejar
        el win32_version_value a 0
        '''
        pointer_position = self.handle.tell()

        self.stop_handle()

        op_header = self.binary_.optional_header

        op_header.win32_version_value = 0

        self.binary_.write(self.path)

        self.start_handle()

        self.handle.seek(pointer_position,ORIGIN)

    def getSectionAlignment(self):
        '''
        Método para obtener el section alignment del PE
        '''
        op_header = self.binary_.optional_header

        return op_header.section_alignment

    def getFileAlignment(self):
        '''
        Método para obtener el file alignment del PE
        '''
        op_header = self.binary_.optional_header

        return op_header.file_alignment

    def getImageBase(self):
        '''
        Método para obtener la imagen base del binario
        '''
        op_header = self.binary_.optional_header

        return op_header.imagebase

        