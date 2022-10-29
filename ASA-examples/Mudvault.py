#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""MUD certificate installer. See grasp.py for license, copyright, and disclaimer."""

from subprocess import run
from tkinter import Tk
from tkinter.filedialog import askopenfilename
import time
import os

def out(reason):
    """Support function"""
    print(reason)
    time.sleep(10)
    exit()
if os.name != 'nt':
    if os.getuid():
        out('You must have root privilege to run this program, e.g. sudo python3 Mudvault.py')    

print('This program will add a PEM format certificate file to the MUD vault.')
print('Please select a file in the dialog box...')
time.sleep(2)
     
Tk().withdraw() # we don't want a full GUI
PEMfile = askopenfilename()

try:
    file = open(PEMfile, "r")
    pem = file.read()
except:
    out("Cannot open PEM file")

cmd = ['openssl', 'x509', '-in', PEMfile, '-noout']
x = run(cmd)
#print(x)
if x.returncode != 0:
    out("PEM file invalid")
if os.name == 'nt':
    syspath = os.environ['PATH']
    if 'OpenSSL' in syspath:
        syspath = syspath.replace('\\','/')
        head,tail = syspath.split('OpenSSL', maxsplit=1)
        _,_,head = head.rpartition(';')
        tail,_ = tail.split('/', maxsplit=1)
        CAfile = head+'OpenSSL'+tail+"/certs/mud-certs.pem"
        if not os.path.exists(CAfile):
            print("Will create vault at "+CAfile)
    else:
        out("Cannot find OpenSSL directory")
else:  #assume Linux
    CAfile = '/etc/ssl/certs/mud-certs.pem'
    if not os.path.exists(CAfile):
        print("Will create vault at "+CAfile)

file = open(CAfile,"a")
file.write(pem)
file.close()
out("Certificate added to MUD vault")
