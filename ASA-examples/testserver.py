#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import grasp
import threading
import time

####################################
# Thread to handle an EX3 negotiation
####################################

class negotiator(threading.Thread):
    """Thread to negotiate obj3 as master"""
    def __init__(self, shandle, nobj):
        threading.Thread.__init__(self)
        self.shandle = shandle
        self.nobj = nobj

    def run(self):
        answer=self.nobj
        shandle=self.shandle
        
        grasp.ttprint("listened, answer",answer.name, answer.value)
        grasp.tprint("Got message:", answer.value)
        err = False
        while not err:
            err, stuff = grasp.grecv(asa_handle, shandle, 60000)
            if not err:
                grasp.tprint("Peer said", stuff)
                tweet = input("Your message:")
                err = grasp.gsend(asa_handle, shandle, tweet)
        grasp.tprint("Send/recv error:",grasp.etext[err])
        #all errors are fatal, the session is dead
        grasp.tprint("End of session")
        

grasp.tprint("==========================")
grasp.tprint("ASA TestServer is starting up.")
grasp.tprint("==========================")
grasp.tprint("TestServer  is a demonstration Autonomic Service Agent.")
grasp.tprint("It just tests out gsend() and grecv() by talking to its peer")
grasp.tprint("On Windows or Linux, there should be a nice window")
grasp.tprint("that displays the talking process.")
grasp.tprint("==========================")

time.sleep(8) # so the user can read the text

####################################
# Register ASA/objectives
####################################

name = "TestServer "
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

###################################
# Negotiate EX3 as listener for ever
###################################
grasp.tprint("Ready to negotiate EX3 as server")

while True:
    #start of a negotiating session

    obj3.value = "Hello!"
    
    #attempt to listen for negotiation
    err, shandle, answer = grasp.listen_negotiate(asa_handle, obj3)
    if err:
        grasp.tprint("listen_negotiate error:",grasp.etext[err])
        time.sleep(5) #to calm things if there's a looping error
    else:
        #got a new negotiation request; kick off a separate negotiator
        #so that multiple requests can be handled in parallel
        negotiator(shandle, answer).start()

