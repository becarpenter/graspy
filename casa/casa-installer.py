#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""This is a proof of concept for a token installer for CASA,
Corporate Authorized Signing Authority, described in
draft-carpenter-anima-otp-casa. 
"""

# Released under the BSD "Revised" License.
#                                                     
# Copyright (C) 2026 Brian E. Carpenter.                  
# All rights reserved.

# 20260903 First version

from tkinter import Tk
from tkinter.filedialog import askdirectory
from tkinter.messagebox import askokcancel, askyesno, askquestion, showinfo
import time
import os
import shutil

from casa_setup import *
from casa_odevid import create_odevid

# set up file names

fpath = env_path + "/pledge"
key_file = fpath + "/odevid_key.pem"
cert_file = fpath + "/odevid_cert.pem"
ca_file = fpath + "/cacert.pem"

# Start of main program

stick = None

run_from = os.path.dirname(os.path.abspath(__name__))
if len(run_from) == 3 and run_from.endswith(":\\"):
    stick = run_from    # Running from memory stick on Windows
elif run_from.startswith("/media/"):
    stick = run_from    # Running from memory stick on Linux (Mint)

if not os.path.exists(fpath):
    os.mkdir(fpath)     # Create directory if needed

if os.path.exists(key_file):
    crash("Pledge already has token. No action taken.")

Tk().withdraw()  # we don't want a full GUI    
T = "CASA token installer"

if not stick:
    showinfo(title=T, message="Need an APDL; insert memory stick")
    stick = askdirectory(title="Select APDL directory")
atokens = rf(stick+"/atokens.bin", token_l)
aflags = rf(stick+"/aflags.bin", 1)
showinfo(title=T, message="APDL read")

# Find a free token
for i in range(len(atokens)):
    if aflags[i] == FREE:
        try:
            #print(atokens[i].hex())
            create_odevid(atokens[i].hex(), key_file, cert_file)
            aflags[i] = CLAIMED
            wf(stick+"/aflags.bin", aflags)
##            shutil.copy(stick+"/cacert.pem", ca_file)
            showinfo(title=T, message="ODevID certificate and private key installed")
            crash("Installer will exit in 10s")
        except Exception as E:
            showinfo(title=T, message="Error: "+ str(E))
            crash("Installer cannot recover")
showinfo(title=T, message="APDL has no free tokens")
crash("Installer will exit")

