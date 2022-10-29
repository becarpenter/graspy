#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import grasp
import time

grasp.tprint("==========================")
grasp.tprint("ASA TestClient is starting up.")
grasp.tprint("==========================")
grasp.tprint("TestClient is a demonstration Autonomic Service Agent.")
grasp.tprint("It just tests out gsend() and grecv() by talking to its peer")
grasp.tprint("On Windows or Linux, there should be a nice window")
grasp.tprint("that displays the talking process.")
grasp.tprint("==========================")

time.sleep(8) # so the user can read the text

####################################
# Register ASA/objectives
####################################

name = "TestClient"
err,asa_handle = grasp.register_asa(name)
if err:
    exit()
grasp.tprint("ASA", name, "registered OK")    

obj3 = grasp.objective("EX3")
obj3.neg = True

err = grasp.register_obj(asa_handle,obj3)
if not err:
    grasp.tprint("Objective EX3 registered OK")
else:
    exit()

grasp.init_bubble_text(name)

grasp.tprint("Ready to negotiate EX3 as client")

failct = 0

while True:
    #start of a negotiating session
    obj3.value = "Start"
    #discover a peer
    if failct > 3:
        failct = 0
        grasp.tprint("Flushing EX3 discovery")
        _, ll = grasp.discover(asa_handle, obj3, 1000, flush = True)
    else:
        _, ll = grasp.discover(asa_handle, obj3, 1000)
    if ll==[]:
        grasp.tprint("Discovery failed")
        failct += 1
        continue
    grasp.ttprint("Discovered locator", ll[0].locator)
    #attempt to negotiate

    grasp.tprint("Session starting")   
    err, shandle, answer = grasp.req_negotiate(asa_handle, obj3, ll[0], None, noloop=True)

    if err == grasp.errors.noReply:
        #session is available
        err = False
        while not err:
            tweet = input("Your message:")
            err = grasp.gsend(asa_handle, shandle, tweet)
            if not err:
                err, reply = grasp.grecv(asa_handle, shandle, 60000)
                if not err:
                    grasp.tprint("Peer replied:", reply)
        grasp.tprint("Send/recv error:",grasp.etext[err])
        #all errors are fatal, the session is dead
        grasp.tprint("End of session")
        continue
    elif err:
        if err==grasp.errors.declined and answer!="":
            _e = answer
        else:
            _e = grasp.etext[err]
        grasp.tprint("req_negotiate error:", _e)
        failct += 1
        grasp.tprint("Fail count", failct)
        time.sleep(5) #to calm things if there's a looping error
    elif (not err) and shandle:
        grasp.tprint("Unexpected response")
        grasp.ttprint("requested, session_handle:",shandle,"answer",answer)
        grasp.tprint("Peer said",answer.value)
        
        
    #end of a negotiating session
    time.sleep(5) #to keep things calm...
