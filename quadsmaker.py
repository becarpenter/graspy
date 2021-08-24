#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""########################################################
########################################################
#                                                     
# Make a QUADS keyset          
#                                                                                                                                    
# Module name is 'quadsmaker'
#
# See grasp.py for license, copyright, and disclaimer.                         
#                                                     
########################################################
########################################################"""

import getpass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


##########################################
#                                        #
# Make a QUADS keyset                    #
#                                        #
##########################################


secret_salt = b'\xf4tRj.t\xac\xce\xe1\x89\xf1\xfb\xc1\xc3L\xeb'
password = None
confirm = 1
print("Please enter the keying password for the domain.")
while password != confirm:
    password = bytes(getpass.getpass(), 'utf-8')
    confirm = bytes(getpass.getpass("Confirm: "), 'utf-8')      
    if password != confirm:
        print("Mismatch, try again.")

if password == b'':
    print("No keys will be generated")
else:
    print("Password accepted")

    kdf = PBKDF2HMAC(
          algorithm=hashes.SHA256(),
          length=32,
          salt=secret_salt,
          iterations=100000,
          backend=default_backend()
     )

    backend = default_backend()
    key = kdf.derive(password)
    _skip = key[0]%10
    iv =  key[_skip:_skip+16]

    #print("key="+str(key))
    #print("iv="+str(iv))

    file = open(r"quadsk.py","w")
    file.write("key="+str(key)+"\n")
    file.write("iv="+str(iv)+"\n")
    file.close()
    print("quadsk.py saved OK")
    
 
