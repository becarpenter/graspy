#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""########################################################
########################################################
# getter is a demonstration Autonomic Service Agent.
# It supports the unregistered GRASP objective 411:mvFile
# in order to request a file from a server ASA
#
#
# Released under the BSD 2-Clause "Simplified" or "FreeBSD"
# License as follows:
#                                                     
# Copyright (C) 2018 Brian E. Carpenter.                  
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
########################################################"""


import os
if os.name!="nt":
    import sys
    sys.path.append('IETF stuff/anima/graspy')

import grasp
import time
import cbor
import os


###################################
# Support function for CBOR coded
# objective value
###################################

def detag(val):
    """ Decode CBOR if necessary
        -> decoded_object, was_CBOR"""
    try:
        return cbor.loads(val), True
    except:
        try:
            if val.tag == 24:
                return cbor.loads(val.value), True
        except:
            return val, False


###################################
# Function to negotiate as initiator
# to get DNS records
###################################

def get_file(fn):
    """Get a single file"""
    global requested_obj
    global failct
    global directory
    #start of a negotiating session
    requested_obj.value = fn
    requested_obj.loop_count = 10 #allows for some fragmentation

    #prepare file path for result   
    try:
        #strip C:/brian/docs for xfer from Windows to Linux
        _, fpath = fn.split("C:/brian/docs/")
    except:
        fpath = directory+fn
       
    grasp.tprint("Asking for",requested_obj.value)
    
    #discover a peer
    if failct > 3:
        failct = 0
        grasp.tprint("Flushing", requested_obj.name, "discovery")
        _, ll = grasp.discover(asa_nonce, requested_obj, 1000, flush = True)
    else:
        _, ll = grasp.discover(asa_nonce, requested_obj, 1000)
    if ll==[]:
        grasp.tprint("Discovery failed")
        failct += 1
        return
  
    grasp.ttprint("Discovered locator", ll[0].locator)
    
    #attempt to negotiate
    
    reply = b''
    err, snonce, received_obj = grasp.req_negotiate(asa_nonce, requested_obj, ll[0], 5000)
    if err:
        if err==grasp.errors.declined and received_obj!="":
            _e = received_obj
        else:
            _e = grasp.etext[err]
        grasp.tprint("req_negotiate error:", _e)
        failct += 1
        grasp.tprint("Fail count", failct)
    elif (not err) and snonce:
        grasp.ttprint("requested, session_nonce:",snonce,"received_obj",received_obj)
        grasp.ttprint("Received reply",received_obj.value)
        looping = True
        first = True
        while looping:
            grasp.ttprint("received_obj is", received_obj.value)
            if first and (received_obj.value == b''):
                grasp.tprint("File not found")
                looping = False
            elif received_obj.value == b'':
                #got the last block
                looping = False
                file.close()
                err = grasp.end_negotiate(asa_nonce, snonce, True)
                if not err:
                    grasp.tprint("Transfer succeeded")
                else:
                    grasp.tprint("end_negotiate error:",grasp.etext[err])
            elif len(received_obj.value):
                if first:
                    file = open(fpath, "wb")
                    grasp.tprint("Starting transfer")
                #write a block and go again                
                file.write(received_obj.value)
                received_obj.value = "ACK"
                received_obj.loop_count += 1
                grasp.ttprint("Sending ACK for more")             
                err,temp,received_obj = grasp.negotiate_step(asa_nonce, snonce, received_obj, 1000)
                if err:
                    if err==grasp.errors.declined and received_obj!="":
                        _e = received_obj
                    else:
                        _e = grasp.etext[err]
                    grasp.tprint("negotiate_step error:",_e)
                    looping = False
                grasp.ttprint("Reply to ACK:", err, temp, received_obj)
            
            first = False
    else:
        #immediate end, strange        
        grasp.tprint("Unexpected reply", received_obj.value)

    #end of a negotiating session
    time.sleep(5) #to keep things calm...
    return

grasp.tprint("========================")
grasp.tprint("ASA getter is starting up.")
grasp.tprint("========================")
grasp.tprint("getter is a demonstration Autonomic Service Agent.")
grasp.tprint("It acts as a client, fetching files.")
grasp.tprint("On Windows or Linux, there should be a nice window")
grasp.tprint("that displays the process.")
grasp.tprint("========================")

####################################
# General initialisation
####################################

grasp.skip_dialogue(selfing=True)
time.sleep(8) # so the user can read the text
failct = 0    # fail counter to control discovery retries

####################################
# Register ASA/objectives
####################################

err, asa_nonce = grasp.register_asa("getter")
if not err:
    grasp.tprint("ASA getter registered OK")
else:
    exit()

#This objective is for the negotiating test
requested_obj = grasp.objective("411:mvFile")
requested_obj.neg = True
requested_obj.loop_count = 4

err = grasp.register_obj(asa_nonce,requested_obj)
if not err:
    grasp.tprint("Objective", requested_obj.name, "registered OK")
else:
    exit()
    

###################################
# Set up pretty printing
###################################         


grasp.init_bubble_text("getter")
grasp.tprint("Ready to negotiate", requested_obj.name,"as requester")

if os.name=="nt":
    directory = "got\\"
else:
    directory = "got/"

###################################
# Main loop
################################### 
while True:    
    get_file(input('File name:'))

  
