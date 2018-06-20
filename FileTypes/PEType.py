#-*- coding: utf-8 -*-

'''
Class for PE files, here we have methods to do
the disinfection process.


@file: PEType.py
@version: 0.1
@author: Fare9
'''


import lief
import os,os.path
import sys
import binascii

from lief import parse
from lief import is_pe,is_elf,is_macho

from Constants import ORIGIN,CURRENT,END
from Constants import SECTION_ALIGNMENT,FILE_ALIGNMENT


class PE_File():
    '''
    Class to manage PE file type,
    these will have handle to use as a file for open it,
    write on it, read from it, close it. And it will have
    binary type from lief library
    '''
    def __init__(self,path):
        '''
        Class constructor, start variables

        :param str path: path to file
        '''
        self.path = path
        self.file_size = os.path.getsize(self.path)
        self.handle = None
        self.binary_ = None
        self.type = 'PE_File'

        self._start_binary()
        self._start_handle()

    # private methods
    def _start_binary(self):
        '''
        Method to start lief binary with parameter path for the object

        :return: None
        '''
        self.binary_ = parse(self.path)

    def _start_handle(self):
        '''
        Method to start file handle

        :return: None
        '''
        try:
            self.handle = open(self.path,'r+b')
        except Exception as e:
            raise type(e)(e.message + ' happened at _start_handle in PEType.py')

    def _stop_handle(self):
        '''
        Method to close the file handle.

        :return: None
        '''
        self.handle.close()

    def _saveChanges(self):
        '''
        Method to save lief changes, it is necessary get 
        the opened file pointer, close it, save file with lief
        and finally re-open it and restablish pointer.

        :return: None
        '''
        pointer_position = self.handle.tell()

        self._stop_handle()

        self.binary_.write(self.path)

        self._start_handle()

        self.handle.seek(pointer_position,ORIGIN)

    def _move_file_rva(self,rva,seek_type):
        '''
        Method to move file pointer, to move it 
        we will take a file RVA in memory, and then
        we will do a seek from the starting point
        given by user

        :param int rva: rva to move on physical file,
                        we use the offset beneath
        :param int seek_type: value that say from where to move
                              it can be only: ORIGIN,CURRENT y END
        :return: None
        '''
        try:
            offset_to_move = self.binary_.rva_to_offset(rva)
            self.handle.seek(offset_to_move,seek_type)
        except Exception as e:
            raise type(e)(e.message + ' happened at _move_file_rva in PEType.py')

    def _read_file_rva(self,number_of_bytes):
        '''
        Method to read the file. File could have moved before
        using _move_file_rva

        :param int number_of_bytes: Number of bytes to read
        :return: buffer with bytes read in hex
        '''
        try:
            buffer_ = self.handle.read(number_of_bytes)
            buffer_ = int(binascii.hexlify(buffer_),16)
            return buffer_
        except Exception as e:
            raise type(e)(e.message + ' happened at _read_file_rva in PEType.py')

    def _write_file_rva(self,buffer_):
        '''
        Method to write in the file. It could have moved
        using _move_file_rva

        :param chr buffer_: byte to write at file 
        :return: None
        '''
        try:
            self.handle.write(buffer_)
        except Exception as e:
            raise type(e)(e.message + ' happened at _write_file_rva in PEType.py')

    def _truncate_file(self,size):
        '''
        Method to truncate file, with or without specified size

        :param_optional int size: size of file to truncate (optional)
        :return: None
        '''
        try:
            if size:
                self.handle.truncate(size)
            else:
                self.handle.truncate()
        except Exception as e:
            raise type(e)(e.message + ' happened at truncate_file in PEType.py')

    # métodos públicos
    def get_offset_from_rva(self,rva):
        '''
        Method to get the file offset from a RVA.

        :param int rva: rva que buscar como offset
        :return: offset en el archivo físico.
        '''
        try:
            offset = self.binary_.rva_to_offset(rva)
            return offset
        except Exception as e:
            raise type(e)(e.message + ' happens at get_offset_from_rva in PEType.py')

    def truncateOverHere(rva,size);
        '''
        Method to truncate file from an RVA, 
        you can truncate everything from that RVA or
        you can take optional size.

        :param int rva: rva to move in the file
        :param int size (opcional): size to truncate file
        :return: None
        '''
        self._move_file_rva(rva,ORIGIN)
        self._truncate_file(size)

    def getRVAEntryPoint(self):
        '''
        Method to get Entry Point RVA from PE Header

        :return: Entry Point value from Optional header,
        '''
        op_header = self.binary_.optional_header

        return op_header.addressof_entrypoint

    def setRVAEntryPoint(self,rva):
        '''
        Method to set RVA Entry Point of that file.
        We stop handle, 
        Método para establecer el RVA del archivo.
        Paramos el handle, y lo volvemos abrir, para 
        que se recargue en disco

        :param dword rva: RVA a establecer del archivo.
        :return: None
        '''   

        pointer_position = self.handle.tell()

        self._stop_handle()

        op_header = self.binary_.optional_header

        op_header.addressof_entrypoint = rva

        self.binary_.write(self.path)

        self._start_handle()

        self.handle.seek(pointer_position,ORIGIN)

    def getSizeOfCode(self):
        '''
        Método para obtener el Size of code del bianrio

        :return: Valor del size of code en la cabecera del archivo
        '''
        op_header = self.binary_.optional_header

        return op_header.sizeof_code

    def setSizeOfCode(self,value):
        '''
        Método para establecer el nuevo valor de size of code

        :param int value: nuevo valor para el size of code.
        :return: None
        '''
        pointer_position = self.handle.tell()

        self._stop_handle()

        op_header = self.binary_.optional_header

        op_header.sizeof_code = value

        self.binary_.write(self.path)

        self._start_handle()

        self.handle.seek(pointer_position,ORIGIN)

    def getSizeOfImage(self):
        '''
        Método para obtener el size of image del archivo

        :return: valor del size of image en la cabecera.
        '''
        op_header = self.binary_.optional_header

        return op_header.sizeof_image

    def setSizeOfImage(self,value):
        '''
        Método para establecer el SizeOfImage

        :param int value: Valor a establecer en la cabecera de nuevo
        '''
        pointer_position = self.handle.tell()

        self._stop_handle()

        op_header = self.binary_.optional_header

        op_header.sizeof_image = value

        self.binary_.write(self.path)

        self._start_handle()

        self.handle.seek(pointer_position,ORIGIN)

    def getVirtualSize(self):
        '''
        Método para obtener el virtual size del archivo

        :return: valor de virtual size en la cabecera
        '''
        op_header = self.binary_.optional_header

        return op_header.virtual_size

    def checkSign(self,value):
        '''
        Método para checkear si un archivo está firmado
        por algún tipo de virus con algún valor.

        :param dword value: firma del virus
        :return: booleano indicando si la cabecera es igual a la firma dada.
        '''
        op_header = self.binary_.optional_header

        return op_header.win32_version_value == value

    def cleanSign(self):
        '''
        Método para quitar la firma de un virus, y dejar
        el win32_version_value a 0

        :return: None
        '''
        pointer_position = self.handle.tell()

        self._stop_handle()

        op_header = self.binary_.optional_header

        op_header.win32_version_value = 0

        self.binary_.write(self.path)

        self._start_handle()

        self.handle.seek(pointer_position,ORIGIN)

    def getSectionAlignment(self):
        '''
        Método para obtener el section alignment del PE.

        :return: valor del section alignment en la cabecera
        '''
        op_header = self.binary_.optional_header

        return op_header.section_alignment

    def getFileAlignment(self):
        '''
        Método para obtener el file alignment del PE.

        :return: valor del file alignment en la cabecera.
        '''
        op_header = self.binary_.optional_header

        return op_header.file_alignment

    def getImageBase(self):
        '''
        Método para obtener la imagen base del binario

        :return: método para obtener la imagen base de un binario de la cabecera.
        '''
        op_header = self.binary_.optional_header

        return op_header.imagebase

    def section_from_rva(self,rva):
        '''
        Método para obtener la sección dado un rva.
        Este se usará para otros métodos.

        :return: retorna la sección correspondiente al rva dado
        '''
        return self.binary_.section_from_rva(rva)

    def alignSizeOfCode(self,type_of_alignment,virus_size):
        '''
        Método para quitar el size of code el virus_size y la
        alineación

        :param int type_of_alignment: tipo de alineación es un valor de
            las constantes SECTION_ALIGNMENT o FILE_ALIGNMENT
        :param int virus_size: tamaño del virus
        '''
        try:
            if type_of_alignment == SECTION_ALIGNMENT:
                alignment = self.getSectionAlignment()
            elif type_of_alignment == FILE_ALIGNMENT:
                alignment = self.getFileAlignment()

            x = self.getSizeOfCode() - virus_size
            rest = x % alignment 
            original_size = x - rest
            self.setSizeOfCode(original_size)
        except Exception as e:
            raise type(e)(e.message() + ' happened at alignSizeOfCode in PEType.py')

    def RVA_Seek(self,rva,seek_type):
        '''
        Método para moverse a través del binario a base de
        RVAs, en disco será necesario moverse por offsets
        la clase hará el trabajo del cambio

        :param int rva: RVA a moverse por el archivo
        :param int seek_type: lugar desde donde moverse los valores
                permitidos serán ORIGIN, CURRENT y END
        ''' 
        if ( (seek_type != ORIGIN) and (seek_type != CURRENT) and (seek_type != END))
            raise Exception("Method of seek_type not supported")

        self._move_file_rva(rva,seek_type)

    def RVA_Read(self,size_):
        '''
        Método para leer del binario, admitirá un tamaño a leer

        :param int size_: tamaño a leer del binario
        :return: buffer leido
        '''
        return self._read_file_rva(size_)

    def RVA_Write(self,buffer_):
        '''
        Método para escribir en el binario, admite un buffer
        de tamaño que sea
        '''
        self._write_file_rva(buffer_)

    def fixSection(self,section,size,type_of_alignment):
        '''
        Método para arreglar una sección del código

        :param section section: Objeto tipo section que usaremos para arreglar el código
        :param int size: tamaño que usar para restar.
        :param int type_of_alignment: tipo de alineación o tamaño alineación
        '''
        if type_of_alignment == SECTION_ALIGNMENT:
            alignment = self.getSectionAlignment()
        elif type_of_alignment == FILE_ALIGNMENT:
            alignment = self.getFileAlignment()
        else:
            alignment = type_of_alignment

        sizeOfRawData = section.sizeof_raw_data

        x = sizeOfRawData - size
        rest = x % alignment
        sizeOfRawData = x - rest

        section.sizeof_raw_data = sizeOfRawData
        section.virtual_size = sizeOfRawData

        self._saveChanges()

    def fixSizeOfImage(self,lastSection):
        '''
        Método para arreglar el sizeOfImage del binario
        como sizeof_raw_data + virtual_address de la última
        sección

        :param section lastSection: última sección del binario
        '''
        sizeOfRawData = lastSection.sizeof_raw_data
        virtual_address = lastSection.virtual_address   

        value = sizeOfRawData + virtual_address

        self.setSizeOfImage(value)

    def killBinary(self):
        '''
        Método para finalizar el binario

        :return: None
        '''
        self._stop_handle()
        self.binary_ = None


