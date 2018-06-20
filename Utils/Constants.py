#-*- coding: utf-8 -*-
'''
Constant values for library, you can add here what you want

@file: Constants.py
@version: 0.1
@author: Fare9
'''


'''
Constants for seek_type
these values are used with seek function
inside the classes of file types 
'''
ORIGIN  = 0
CURRENT = 1
END     = 2

# Constants to align files
SECTION_ALIGNMENT   = 0
FILE_ALIGNMENT      = 1

'''
Constants to know if file is:
    - MUTATION: file modified from original
    - NOVIRUS: is not our virus
    - CLEANED: cleaned from virus
'''
MUTATION            = -1
NOVIRUS             = -2
CLEANED             =  0