#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""########################################################
########################################################
# GetDNSSD is a demonstration Autonomic Service Agent.
# It supports the unregistered GRASP objective 411:DNSSD
# in order to fetch DNS-SD records on behalf of a client ASA
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
import threading
import time
import sys
import cbor
import dns.resolver

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

####################################
# Support functions for negotiator
####################################

def endit(snonce, r):
    """Send end_negotiate with reason string"""
    grasp.tprint("Failed", r)
    err = grasp.end_negotiate(asa_nonce, snonce, False, reason=r)
    if err:
        grasp.tprint("end_negotiate error:",grasp.etext[err])

def resolve(n,q):
    """Resolve a single domain and return the RR"""
    try:
        grasp.ttprint("Resolving",n,q)
        a=dns.resolver.query(n,q)
        grasp.ttprint("Got",a)
        return a
    except:
        return []

def fix_string(s):
    """Replace escapes by raw bytes and return as a Unicode string"""
    r = ''
    while True:
        try:
            
            p1,p2 = s.split('\\', maxsplit=1)

            try:
                #replace escape sequence by byte
                ch = chr(int(p2[0:3]))
            except ValueError:
                #looks like an isolated backslash, not a Unicode escape
                #but we have to leave it in place for SRV lookup
                #to succeed
                ch='\\'+p2[0:3]
            r += p1 + ch
            s = p2[3:]
        except ValueError:
            r += s
            return str(bytes(r,encoding='raw_unicode_escape'),encoding='utf-8')
        

####################################
# Thread to handle a negotiation
####################################

class negotiator(threading.Thread):
    """Thread to negotiate objective as master"""
    def __init__(self, snonce, nobj):
        threading.Thread.__init__(self)
        self.snonce = snonce
        self.nobj = nobj

    def run(self):
        answer=self.nobj
        snonce=self.snonce
        
        answer.value, _cbor = detag(answer.value)
        if _cbor:
            grasp.tprint("CBOR value decoded")

        grasp.tprint("Got request for", answer.value)
        if answer.dry:
            endit(snonce,"Dry run not supported")
        else:
            reply = []
            reply_size = 0
            #Look for PTR record first
            
            a = resolve(answer.value,'PTR')
            
            for r in a:
                
                #extract the name
                raw_name = str(r)
                #decode Unicode escapes
                fixed_name = fix_string(raw_name)
                #remove bogus escapes
                name = fixed_name.replace("\\","")
                                
                grasp.tprint("Got PTR name:",name)
                grasp.ttprint("Raw name:",raw_name)

                #remember where we are in the list
                reply_mark = len(reply)

                #add RR to reply
                reply.append('PTR '+ name)

                #look for other records
                a = resolve(fixed_name,'SRV')
                for r in a:
                    srv_reply = []
                    grasp.ttprint("Got SRV", str(r))
                    srv_reply.append('SRV '+str(r))

                    #parse SRV record to extract the domain

                    _,_,_,domain = str(r).split(' ')
                    grasp.ttprint("Got domain", domain)
                    
                    #look for address records
                    a = resolve(domain,'AAAA')
                    for r in a:
                        grasp.ttprint("Got AAAA", str(r))
                        srv_reply.append('AAAA '+str(r))
                    a = resolve(domain,'A')
                    
                    for r in a:
                        grasp.ttprint("Got A", str(r))
                        srv_reply.append('A '+str(r))

                    #add RRs to reply
                    reply.append(srv_reply)
                    
                a = resolve(name,'TXT')
                for r in a:
                    grasp.ttprint("Got TXT", str(r))
                    #Note that TXT records may include quotes
                    reply.append('TXT '+str(r))

                #fragment before reaching 2000 bytes
                _l = len(cbor.dumps(reply))
                if _l > reply_size + 1900:
                        #getting big, mark to fragment before previous PTR
                        grasp.tprint("Fragmenting before", _l)
                        reply_size += (_l + 5)
                        reply.insert(reply_mark, 'MORE')
                
            #reply is now a (possibly empty) list of RRs
            if len(reply):      
                grasp.tprint("Found",reply)
            else:
                reply = ['NXDOMAIN']
                grasp.tprint("No record in DNS")

            #grasp.tprint("Object length",sys.getsizeof(reply),"bytes")
            #creply=cbor.dumps(reply)
            #grasp.tprint("CBOR length",len(creply),"bytes")

            while len(reply):

                if 'NXDOMAIN' in reply:
                    piece = []
                    reply = []
                elif 'MORE' in reply:
                    grasp.tprint("Oversized reply fragmented")
                    mx = reply.index('MORE')+1
                    piece = reply[:mx]
                    reply = reply[mx:]
                else:
                    piece = reply
                    reply = []
                    
                answer.value = piece                  
                
                if _cbor:
                    answer.value=cbor.dumps(answer.value)
                #send reply as negotiation step
                err,temp,answer = grasp.negotiate_step(asa_nonce, snonce, answer, 1000)
                grasp.ttprint("Negotiation step gave:", err, temp, answer)
                if (not err) and temp==None:
                    grasp.tprint("Reply step succeeded")                 
                elif not err:
                    answer.value, _ = detag(answer.value)
                    if _:
                        grasp.tprint("CBOR value decoded")
                        
                    if not len(reply):
                        grasp.tprint("Unexpected reply: loop count", answer.loop_count,
                                     "value",answer.value)
                        endit(snonce, "Unexpected reply")
                else:    
                    #other end rejected or loop count exhausted
                    reply = [] #to get us out of the loop
                    if err==grasp.errors.loopExhausted:
                        # we need to signal the end
                        endit(snonce, grasp.etext[err])
                    else:
                        grasp.tprint("Failed:",grasp.etext[err])
                        

        #end of negotiation

grasp.tprint("==========================")
grasp.tprint("ASA GetDNSSD is starting up.")
grasp.tprint("==========================")
grasp.tprint("GetDNSSD is a demonstration Autonomic Service Agent.")
grasp.tprint("It runs indefinitely as a gateway to DNS,")
grasp.tprint("intended to fetch SRV and related records,")
grasp.tprint("to proxy DNS-SD for GRASP nodes.")
grasp.tprint("It is implemented using a negotiation objective")
grasp.tprint("that can handle overlapping requests.")
grasp.tprint("On Windows or Linux, there should be a nice")
grasp.tprint("window that displays the process.")
grasp.tprint("==========================")

####################################
# General initialisation
####################################

#grasp.test_mode = True # set if you want detailed diagnostics
time.sleep(8) # so the user can read the text

####################################
# Register ASA/objective
####################################

err,asa_nonce = grasp.register_asa("GetDNSSD")
if not err:
    grasp.tprint("ASA GetDNSSD registered OK")

else:
    exit()
    
obj1 = grasp.objective("411:DNSSD")
obj1.loop_count = 4
obj1.neg = True


err = grasp.register_obj(asa_nonce,obj1)
if not err:
    grasp.tprint("Objective", obj1.name, "registered OK")
else:
    exit()

###################################
# Hack to get round nameservers that can't resolve the test domain
###################################

try:
    dns.resolver.query('_printer._sub._http._tcp.dns-sd.org.','PTR')
except:
    dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
    dns.resolver.default_resolver.nameservers = [ '2001:4860:4860::8888',
                                                  '2001:4860:4860::8844',
                                                  '8.8.8.8', '8.8.4.4' ]
    grasp.tprint("Couldn't resolve test domain, switched to Google nameservers")

###################################
# Set up pretty printing
###################################

grasp.init_bubble_text("GetDNSSD")
grasp.tprint("GetDNSSD is listening")

###################################
# Negotiate as listener for ever
###################################

while True:
    # listen for negotiation request
    err, snonce, answer = grasp.listen_negotiate(asa_nonce, obj1)
    if err:
        grasp.tprint("listen_negotiate error:",grasp.etext[err])
        time.sleep(5) #to calm things if there's a looping error
    else:
        #got a new negotiation request; kick off a separate negotiator
        #so that multiple requests can be handled in parallel
        negotiator(snonce, answer).start()



