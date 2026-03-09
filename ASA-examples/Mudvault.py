#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""MUD certificate installer. See grasp.py for license, copyright, and disclaimer."""

#Update 20260309 for Python 3.14 and Windows 11, also improved dialogue

from subprocess import run
from tkinter import Tk
from tkinter.filedialog import askopenfilename, askdirectory
import time
import os
import ssl
import OpenSSL.crypto # You may need to install pyOpenSSL (pip install pyopenssl)

def out(reason):
    """Support function"""
    print(reason+":", "program will exit.")
    time.sleep(10)
    exit()
    
if os.name != 'nt':
    if os.getuid():
        out('You may need root privilege to run this program, e.g. sudo python3 Mudvault.py')    

print('This program will add a PEM format certificate file to the MUD vault.')
print('Please select a PEM file in the dialog box...')
time.sleep(2)
     
Tk().withdraw() # we don't want a full GUI
PEMfile = askopenfilename(title="Select PEM file")

#print(PEMfile)

try:
    file = open(PEMfile, "r")
    pem = file.read()
except:
    out("Cannot open PEM file")

##Commented out old validity check 20260309, it fails with Python3.14 and Windows 11
##cmd = ['openssl', 'x509', '-in', PEMfile] #, '-noout']
##x = run(cmd, shell=True)
##if x.returncode != 0:
##    out("PEM file invalid")

#PEM validity check
try:
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem)
except:
    out("PEM file invalid")

##Commented out 20260309, too system dependent    
##if os.name == 'nt':
##    syspath = os.environ['PATH']
##    if 'OpenSSL' in syspath:
##        syspath = syspath.replace('\\','/')
##        head,tail = syspath.split('OpenSSL', maxsplit=1)
##        _,_,head = head.rpartition(';')
##        tail,_ = tail.split('/', maxsplit=1)
##        CAfile = head+'OpenSSL'+tail+"/tests/certs/mud-certs.pem"
##        if not os.path.exists(CAfile):
##            print("Will create vault at "+CAfile)
##    else:
##        out("Cannot find OpenSSL directory")
##else:  #assume Linux
##    CAfile = '/etc/ssl/certs/mud-certs.pem'
##    if not os.path.exists(CAfile):
##        print("Will create vault at "+CAfile)


print('Please select a directory for the MUD vault in the dialog box...')
time.sleep(2)
vault_dir = askdirectory(title = "Choose directory for MUD vault")
CAfile = vault_dir + "/mud-certs.pem"
if not os.path.exists(CAfile):
    print("Will create vault at "+CAfile)

file = open(CAfile,"a")
file.write(pem)
file.close()
out("Certificate added to MUD vault")
