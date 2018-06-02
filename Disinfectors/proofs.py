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

# lugar donde se encuentran los stolen_bytes
stolen_bytes_offset = 0x401A05
start_address_offset = 0x401A39
stolen_bytes_size = 0x32

# offset donde se encuentran los bytes cifrados 
# y el tamaño
ciphered_bytes_offset = 0x40102F
ciphered_bytes_size = 0x6A2
key_offset = 0x401A6E

# real entry point (padme guarda el RVA + IMAGE_BASE)
entry_point_real_address_offset = 0x401A7F


virus_size = 0x1452
#virus_size = 0x9FB

def get_delta_offset(binary_):
    '''
    Obtención del delta offset de PADME
    '''
    rva_ep_binario = binary_.getBinaryRVAEntryPoint()

    base_address = binary_.getBinaryImageBase()

    ep_binario = rva_ep_binario + base_address

    first_address = ep_binario + 8

    binary_.RVA_Seek(rva_ep_binario  + 0xC,ORIGIN)

    second_address = binary_.RVA_Read(4)

    second_address = swapBytes(second_address)

    delta_offset = first_address - second_address

    if _debug:
        print "-------------------------------------------"
        print "|             GET DELTA OFFSET            |"
        print "|------------------------------------------"

        print "RVA ep_binario: 0x%x" % (rva_ep_binario)

        print "Binary base address: 0x%x" % (base_address)

        print "First address: 0x%x" % (first_address)

        print "Second address: 0x%x" % (second_address)

        print "Delta offset: 0x%x" % (delta_offset)

    return delta_offset

def decode_ciphered_bytes(binary_,delta_offset):
    '''
    Método para decodificar los bytes codificados por el virus
    cuando se copio en el archivo modificado
    '''
    base_address = binary_.getBinaryImageBase()

    cipher_address = ciphered_bytes_offset + delta_offset

    cipher_rva = cipher_address - base_address

    key_address = key_offset + delta_offset

    key_rva = key_address - base_address

    binary_.RVA_Seek(key_rva,ORIGIN)

    key = binary_.RVA_Read(1)

    for i in range(ciphered_bytes_size):

        binary_.RVA_Seek(cipher_rva + i,ORIGIN)
    
        byte = binary_.RVA_Read(1)        

        byte = byte ^ key

        binary_.RVA_Seek(cipher_rva + i,ORIGIN)

        binary_.RVA_Write(chr(byte))

    if  _debug:
        print "-------------------------------------------"
        print "|             DECIPHER BYTES              |"
        print "-------------------------------------------"

        print "Binary base address: 0x%x" % (base_address)

        print "Ciphered address in memory: 0x%x" % (cipher_address)

        print "Ciphered offset: 0x%x" % (cipher_rva)

        print "Key: 0x%x" % (key)

    print "PADME DECIPHERED"

def restore_entry_point(binary_,delta_offset):
    '''
    Método para restaurar el entry point original del binario
    '''
    base_address = binary_.getBinaryImageBase()

    entry_point_real_address = entry_point_real_address_offset + delta_offset

    entry_point_real_address_rva = entry_point_real_address - base_address

    binary_.RVA_Seek(entry_point_real_address_rva,ORIGIN)

    real_entry_point = binary_.RVA_Read(4)

    real_entry_point = swapBytes(real_entry_point)

    real_entry_point = real_entry_point - base_address

    binary_.setBinaryRVAEntryPoint(real_entry_point)

    if _debug:

        print "-------------------------------------------"
        print "|           RESTORE ENTRY POINT           |"
        print "-------------------------------------------"

        print "Entry point real address: 0x%x" % entry_point_real_address

        print "Entry point real address rva: 0x%x" % entry_point_real_address_rva

        print "Real entry point (this will be the one to be injected in RVA Entry point): 0x%x" % real_entry_point

    print "Entry point fixed"

def restore_stolen_bytes(binary_,delta_offset):
    '''
    Método para restaurar los stolen bytes del archivo
    '''
    base_address = binary_.getBinaryImageBase()

    stolen_bytes_address = stolen_bytes_offset + delta_offset

    stolen_bytes_address_rva = stolen_bytes_address - base_address

    start_address_address_rva = binary_.getBinaryRVAEntryPoint()

    for i in range(stolen_bytes_size):

        binary_.RVA_Seek(stolen_bytes_address_rva + i,ORIGIN)

        byte = binary_.RVA_Read(1)

        binary_.RVA_Seek(start_address_address_rva + i,ORIGIN)

        binary_.RVA_Write(chr(byte))

    if _debug:
        print "-------------------------------------------"
        print "|            RECOVER STOLEN BYTES         |"
        print "-------------------------------------------"

        print "Stolen bytes RVA: 0x%x" % (stolen_bytes_address_rva)

        print "Start address RVA to copy: 0x%x" % (start_address_address_rva)

    print "STOLEN BYTES RECOVERED"



if __name__ == '__main__':

    binario = getFileBinary("strings_modified.exe")


    if binario.checkBinarySign(0x69):
        print '[+] The file is infected by Padme virus'

    start_of_virus_rva = binario.getBinaryRVAEntryPoint()

    my_delta = get_delta_offset(binario)

    decode_ciphered_bytes(binario,my_delta)

    restore_entry_point(binario,my_delta)

    restore_stolen_bytes(binario,my_delta)


    binario.RVA_Seek(start_of_virus_rva,ORIGIN)

    for i in range(virus_size):
        binario.RVA_Write(crh(0))

    binario.killBinary()
