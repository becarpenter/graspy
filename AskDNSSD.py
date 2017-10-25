#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""########################################################
########################################################
# AskDNSSD is a demonstration Autonomic Service Agent.
# It supports the unregistered GRASP objective 411:DNSSD
# in order to request DNS-SD records from a server ASA
#
#
# Released under the BSD 2-Clause "Simplified" or "FreeBSD"
# License as follows:
#                                                     
# Copyright (C) 2017 Brian E. Carpenter.                  
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

import grasp
import time
import cbor


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

def get_dns_info(dom):
    """Obtain and return all DNS-SD records for a domain"""
    global obj3
    global failct
    #start of a negotiating session
    obj3.value = dom
    obj3.loop_count = 10 #allows for some fragmentation


    # As a random test, use CBOR (Tag 24) format for value (should work)
    if not grasp._prng.randint(0,3):
        _cbor = True 
    else:
        _cbor = False   

    # As a random test, request dry run (should fail)
    if not grasp._prng.randint(0,7):
        obj3.dry = True  # random error for testing purposes
    else:
        obj3.dry = False
        
    grasp.tprint("Asking for",obj3.value,"; dry run",obj3.dry,"; Tag 24",_cbor)
    
    #discover a peer
    if failct > 3:
        failct = 0
        grasp.tprint("Flushing", obj3.name, "discovery")
        _, ll = grasp.discover(asa_nonce, obj3, 1000, flush = True)
    else:
        _, ll = grasp.discover(asa_nonce, obj3, 1000)
    if ll==[]:
        grasp.tprint("Discovery failed")
        failct += 1
        return
  
    grasp.ttprint("Discovered locator", ll[0].locator)
    
    #attempt to negotiate
    
    if _cbor:
        #CBORise the value
        obj3.value=cbor.dumps(obj3.value)

    reply = []
    err, snonce, answer = grasp.req_negotiate(asa_nonce, obj3, ll[0], None)
    if err:
        if err==grasp.errors.declined and answer!="":
            _e = answer
        else:
            _e = grasp.etext[err]
        grasp.tprint("req_negotiate error:", _e)
        failct += 1
        grasp.tprint("Fail count", failct)
        time.sleep(5) #to calm things if there's a looping error
    elif (not err) and snonce:
        grasp.ttprint("requested, session_nonce:",snonce,"answer",answer)
        _found_cbor = False
        if _cbor:
            answer.value, _found_cbor = detag(answer.value)

        grasp.ttprint("Received reply",answer.value)
            
        if _cbor != _found_cbor:
            #Anomaly, get me out of here
            grasp.tprint("CBOR anomaly 1 - missing segment?")
            grasp.end_negotiate(asa_nonce, snonce, False,
                                reason="CBOR anomaly 1 - missing segment?")        

        elif not grasp._prng.randint(0,7):
            #######################################################
            # As a random test of robustness, send a bogus response
            answer.value = "rubbish"
            grasp.tprint("Sending rubbish")
            if _cbor:
                #CBORise the value
                answer.value=cbor.dumps(answer.value)                
            err,temp,answer = grasp.negotiate_step(asa_nonce, snonce, answer, 1000)
            grasp.ttprint("Reply to rubbish:", err, temp, answer)
            _found_cbor = False
            if _cbor and (not err):
                answer.value, _found_cbor = detag(answer.value)
            if (not err) and temp==None:
                grasp.tprint("Unexpected answer:", answer.value)
            elif (not err) and _cbor != _found_cbor:
                grasp.tprint("CBOR anomaly 2 - missing segment?")
            elif not err:
                grasp.tprint("Loop count", answer.loop_count,
                             "unexpected answer", answer.value)
                err = grasp.end_negotiate(asa_nonce, snonce, False,
                                          reason="Unexpected answer")
                if err:
                    grasp.tprint("end_negotiate error:",grasp.etext[err])
            else:    
                #other end rejected
                if err==grasp.errors.declined and answer!="":
                    _e = answer
                else:
                    _e = grasp.etext[err]
                grasp.tprint("Peer reject:",_e)
            # End of random test of robustness
            #######################################################
            
        else:
            #Received answer
            looping = True
            while looping:
                grasp.ttprint("Answer is", answer.value)
                if 'MORE' in answer.value:
                    #need to go again                
                    reply += answer.value[:answer.value.index('MORE')]
                    answer.value = "ACK"
                    grasp.tprint("Sending ACK for more")
                    if _cbor:
                        #CBORise the value
                        answer.value=cbor.dumps(answer.value)                
                    err,temp,answer = grasp.negotiate_step(asa_nonce, snonce, answer, 1000)
                    if err:
                        grasp.tprint("negotiate_step error:",grasp.etext[err])
                        looping = False
                    elif _cbor:
                        answer.value, _found_cbor = detag(answer.value)
                        if _cbor != _found_cbor:
                            #anomaly, get me out of here
                            looping = False
                            grasp.end_negotiate(asa_nonce, snonce, False,
                                                reason="CBOR anomaly - missing segment?")
                            grasp.tprint("CBOR anomaly 3 - missing segment?")
                    grasp.ttprint("Reply to ACK:", err, temp, answer)
                else:
                    looping = False
                    reply += answer.value            
                    err = grasp.end_negotiate(asa_nonce, snonce, True)
                    if not err:
                        if len(reply):
                            grasp.tprint("Query succeeded", reply)
                        else:
                            grasp.tprint("Empty result")
                    else:
                        grasp.tprint("end_negotiate error:",grasp.etext[err])
    else:
        #immediate end, strange        
        grasp.tprint("Unexpected reply", answer.value)

    #end of a negotiating session
    time.sleep(5) #to keep things calm...
    return

grasp.tprint("========================")
grasp.tprint("ASA AskDNSSD is starting up.")
grasp.tprint("========================")
grasp.tprint("AskDNSSD is a demonstration Autonomic Service Agent.")
grasp.tprint("It acts as a client, asking for DNS-SD information.")
grasp.tprint("On Windows or Linux, there should be a nice window")
grasp.tprint("that displays the process.")
grasp.tprint("========================")

####################################
# General initialisation
####################################

#grasp.test_mode = True # tell everybody it's a test
time.sleep(8) # so the user can read the text
failct = 0    # fail counter to control discovery retries

####################################
# Register ASA/objectives
####################################

err, asa_nonce = grasp.register_asa("AskDNSSD")
if not err:
    grasp.tprint("ASA AskDNSSD registered OK")
else:
    exit()

#This objective is for the negotiating test
obj3 = grasp.objective("411:DNSSD")
obj3.neg = True
obj3.loop_count = 4

err = grasp.register_obj(asa_nonce,obj3)
if not err:
    grasp.tprint("Objective", obj3.name, "registered OK")
else:
    exit()
    

###################################
# Set up pretty printing
###################################         


grasp.init_bubble_text("AskDNSSD")
grasp.tprint("Ready to negotiate", obj3.name,"as requester")



#main loop
while True:
    #insert test cases here
    get_dns_info('_sip._udp.sip.voice.google.com')
    #get_dns_info('_dmarc.gmail.com')
    #get_dns_info('_http._tcp.dns-sd.org')
    #time.sleep(5)
    get_dns_info('_printer._sub._http._tcp.dns-sd.org.')
    time.sleep(5)
    get_dns_info('_http._tcp.dns-sd.org.')
    time.sleep(5)
