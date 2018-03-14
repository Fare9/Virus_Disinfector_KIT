#-*- coding: utf-8 -*-
'''
Valores constantes de la librería, estos valdrán para distintas llamadas

@author: Fare9
'''


# constantes para el seek_type 
# estos valores son usados en el seek
# dentro de las clases de tipos de
# archivos
ORIGIN  = 0
CURRENT = 1
END     = 2

# Constantes para alinear el archivo
SECTION_ALIGNMENT	= 0
FILE_ALIGNMENT		= 1

# Constantes para designar si ha habido cambios
# o si se ha desinfectado, o si es otro virus
MUTATION			= -1
NOVIRUS				= -2
CLEANED				=  0