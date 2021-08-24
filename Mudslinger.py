#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Demo MUD thing using GRASP. See grasp.py for license, copyright, and disclaimer."""

import grasp
import time
import ipaddress

###################################
# Print obj_registry and flood cache
###################################

def dump_some():
    """Dumps some GRASP internals for debugging."""
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


grasp.tprint("========================")
grasp.tprint("ASA Mudslinger is starting up.")
grasp.tprint("========================")
grasp.tprint("Mudslinger is a demonstration Autonomic Service Agent.")
grasp.tprint("It acts the part of a node that needs to send its")
grasp.tprint("MUD URL to the local MUD manager.")
grasp.tprint("On Windows or Linux, there should be a nice window")
grasp.tprint("that displays the process.")
grasp.tprint("========================")


time.sleep(8) # so the user can read the text


####################################
# Register ASA/objectives
####################################

asa_name = "Mudslinger"
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
# Negotiate MUDURL as initiator to send URL
###################################

grasp.init_bubble_text(asa_name)
grasp.tprint("Ready to negotiate", obj_name, "as requester")

failct = 0
while True:
    obj3.value = input("Enter sample MUD URL:")
    #########this tests an error case##########
    if obj3.value == "magic":
        obj3.value = 987654321
    grasp.ttprint("Starting discovery for", obj_name)
    #discover a peer
    if failct > 3:
        failct = 0
        grasp.tprint("Flushing discovery")
        _, ll = grasp.discover(asa_nonce, obj3, 1000, flush = True)
    else:
        _, ll = grasp.discover(asa_nonce, obj3, 1000)
    if ll==[]:
        grasp.tprint("Discovery failed")
        failct += 1
        continue
    grasp.ttprint("Discovered locator", ll[0].locator)
    
    #attempt to negotiate
    grasp.ttprint("Trying request for:", obj3.value)   
    err, snonce, answer = grasp.req_negotiate(asa_nonce, obj3, ll[0], None)
    if err:
        if err==grasp.errors.declined and answer!="":
            _e = answer
        else:
            _e = grasp.etext[err]
        grasp.tprint("req_negotiate error:", _e)
        failct += 1
        grasp.tprint("Fail count", failct)
        #time.sleep(5) #to calm things if there's a looping error
    elif (not err) and snonce:
        grasp.ttprint("requested, session_nonce:",snonce,"answer",answer)
        grasp.tprint("Unexpected reply:", answer.value)
        #end the session, something is out of whack
        err = grasp.end_negotiate(asa_nonce, snonce, False, reason="Unexpected reply")
        if err:
            grasp.tprint("end_negotiate error:",grasp.etext[err])
        concluded = True
        break               
    else:
        #acceptable answer first time
        grasp.tprint("MUD URL sent OK", answer.value)
        continue
    #end of a negotiating session
    #time.sleep(5) #to keep things calm...
    if grasp.test_mode:
        dump_some()


