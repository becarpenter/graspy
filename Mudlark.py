#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Demo MUD manager using GRASP. See graspy.py for licence and disclaimers."""

import grasp
import threading
import time
import ipaddress
import requests
import json

###################################
# Print obj_registry and flood cache
###################################

def dump_some():
    grasp.tprint("Objective registry contents:")         
    for x in grasp._obj_registry:
        o= x.objective
        grasp.tprint(o.name,"ASA:",x.asa_id,"Listen:",x.listening,"Neg:",o.neg,
               "Synch:",o.synch,"Count:",o.loop_count,"Value:",o.value)
    grasp.tprint("Flood cache contents:")            
    for x in grasp._flood_cache:
        grasp.tprint(x.objective.name,"count:",x.objective.loop_count,"value:",
                     x.objective.value,"source",x.source)
    time.sleep(5)

####################################
# Support function for negotiator
####################################

def endit(snonce, r):
    grasp.tprint("Failed", r)
    err = grasp.end_negotiate(asa_nonce, snonce, False, reason=r)
    if err:
        grasp.tprint("end_negotiate error:",grasp.etext[err])

####################################
# Thread to handle a MUDURL negotiation
####################################

class negotiator(threading.Thread):
    """Thread to negotiate MUDURL as MUD manager"""
    def __init__(self, snonce, nobj):
        threading.Thread.__init__(self)
        self.snonce = snonce
        self.nobj = nobj

    def run(self):
        answer=self.nobj
        snonce=self.snonce        
        grasp.ttprint("listened, answer",answer.name, answer.value)
        grasp.tprint("Got MUD URL", answer.value,
                     "from", ipaddress.IPv6Address(snonce.id_source))
        if grasp.tname(answer.value)!="str":
            endit(snonce, "Not a string")
        elif answer.value[0:8]!="https://":
            endit(snonce, "Not https: scheme")
        #could do other sanity checks
        else:
            #sanity checks passed
            #Here the MUD manager will process the URL
            grasp.tprint("Processing MUD URL now")
            try:
                j = json.loads(requests.get(answer.value).content.decode())
                #got valid JSON, now do some example parsing
                try:
                    grasp.tprint(j['ietf-mud:mud']['last-update'],j['ietf-mud:mud']['systeminfo'])
                except:
                    grasp.tprint("Faulty MUD file")
                try:
                    sig = j['ietf-mud:mud']['mud-signature']
                    grasp.tprint("Signature at",sig)
                except:
                    grasp.tprint("Warning: unsigned MUD file")
            except:                
                grasp.tprint("Faulty URL or faulty JSON")
            #time.sleep(1)
            #we do not signal a result to the peer
            err = grasp.end_negotiate(asa_nonce, snonce, True)
            if err:
                grasp.tprint("end_negotiate error:",grasp.etext[err])
            
         #end of a negotiating session

grasp.tprint("==========================")
grasp.tprint("ASA Mudlark is starting up.")
grasp.tprint("==========================")
grasp.tprint("Mudlark is a demonstration Autonomic Service Agent.")
grasp.tprint("It simulates a Network Management System function")
grasp.tprint("that receives MUD URLs from joining nodes and")
grasp.tprint("acts as a MUD manager per RFC8520.")
grasp.tprint("On Windows or Linux, there should be a nice window")
grasp.tprint("that displays the process.")
grasp.tprint("==========================")

#grasp.test_mode = True # set if you want detailed diagnostics
time.sleep(8) # so the user can read the text

####################################
# Register ASA/objectives
####################################

asa_name = "Mudlark"
err,asa_nonce = grasp.register_asa("asa_name")
if not err:
    grasp.tprint("ASA",asa_name, "registered OK")
else:
    grasp.tprint("ASA registration failure:", grasp.etext[err])
    time.sleep(60)
    exit()

obj_name = "411:MUDURL"
obj3 = grasp.objective(obj_name)
obj3.neg = True

err = grasp.register_obj(asa_nonce,obj3)
if not err:
    grasp.tprint("Objective", obj_name, "registered OK")
else:
    grasp.tprint("Objective registration failure:", grasp.etext[err])
    time.sleep(60)
    exit()

if grasp.test_mode:
    dump_some()


###################################
# Negotiate MUDURL as listener for ever
###################################

grasp.init_bubble_text(asa_name)
grasp.tprint("Ready to negotiate", obj_name, "as listener")

while True:    
    #listen for new negotiation
    err, snonce, answer = grasp.listen_negotiate(asa_nonce, obj3)
    if err:
        grasp.tprint("listen_negotiate error:",grasp.etext[err])
        if grasp.test_mode:
            dump_some()
        time.sleep(5) #to calm things if there's a looping error
    else:
        #got a new negotiation request; kick off a separate negotiator
        #so that multiple requests can be handled in parallel
        negotiator(snonce, answer).start()

