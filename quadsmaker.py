#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""########################################################
########################################################
#                                                     
# Make a QUADS keyset          
#                                                                                                                                    
# Module name is 'quadsmaker'
#
# Released under the BSD 2-Clause "Simplified" or "FreeBSD"
# License as follows:
#                                                     
# Copyright (C) 2019 Brian E. Carpenter.                  
# All rights reserved.
#
# Redistribution and use in source and binary forms, with
# or without modification, are permitted provided that the
# following conditions are met:
#
# 1. Redistributions of source code must retain the above
# copyright notice, this list of conditions and the following
# disclaimer.
#
# 2. Redistributions in binary form must reproduce the above
# copyright notice, this list of conditions and the following
# disclaimer in the documentation and/or other materials
# provided with the distribution.                                  
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS  
# AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED 
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A     
# PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
# THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
# USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)    
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
# IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING   
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
# USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE        
# POSSIBILITY OF SUCH DAMAGE.                         
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
    
 
