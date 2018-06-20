#-*- coding: utf-8 -*-

'''
Useful methods to use inside the files:
    - memory reading
    - PE reading
    - Elf...

@file: Utilities.py
@version: 0.1
@author: Fare9
'''

import struct
from struct import pack,unpack


def swapBytes(number):
    '''
    Convert number from Big-Endian to Little-Endian and vice-versa.

    THANKS TO: @MZ_IAT

    :param int number: number to convert of endianess
    :return: number modified
    '''
    return unpack('>L',pack("<L",number))[0]