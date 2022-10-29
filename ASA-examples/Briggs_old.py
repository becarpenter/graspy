#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import grasp
import threading
import time
import datetime
import cbor
import random

grasp.tprint("==========================")
grasp.tprint("ASA Briggs is starting up (old API).")
grasp.tprint("==========================")
grasp.tprint("Briggs is a demonstration Autonomic Service Agent.")
grasp.tprint("It tests out several basic features of GRASP, and")
grasp.tprint("then runs indefinitely as one side of a negotiation.")
grasp.tprint("It acts as the banker, giving out money, and can")
grasp.tprint("handle multiple overlapping negotiations.")
grasp.tprint("The sum available is random for each negotiation,")
grasp.tprint("and the negotiation timeout is changed at random.")
grasp.tprint("On Windows or Linux, there should be a nice window")
grasp.tprint("that displays the negotiation process.")
grasp.tprint("==========================")


time.sleep(8) # so the user can read the text
_prng = random.SystemRandom() # best PRNG we can get

####################################
# Register ASA/objectives
####################################

err,asa_nonce = grasp.register_asa("Briggs")
if not err:
    grasp.tprint("ASA Briggs registered OK")

else:
    exit()
    
obj1 = grasp.objective("EX1")
obj1.loop_count = 4
obj1.synch = True

err = grasp.register_obj(asa_nonce,obj1)
if not err:
    grasp.tprint("Objective EX1 registered OK")
else:
    exit()

obj2 = grasp.objective("EX2")
obj2.loop_count = 4
obj2.synch = True

err = grasp.register_obj(asa_nonce,obj2,rapid=True)
if not err:
    grasp.tprint("Objective EX2 registered OK")
else:
    exit()

obj3 = grasp.objective("EX3")
obj3.neg = True
obj3.dry = True

err = grasp.register_obj(asa_nonce,obj3)
if not err:
    grasp.tprint("Objective EX3 registered OK")
else:
    exit()

####################################
# Flood EX1 repeatedly
####################################

class flooder(threading.Thread):
    """Thread to flood EX1 repeatedly"""
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        while True:
            time.sleep(60)
            obj1.value = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC from Briggs")
            err = grasp.flood(asa_nonce, 59000, [grasp.tagged_objective(obj1,None)])
            if err:
                grasp.tprint("Flood failure:",grasp.etext[err])
            time.sleep(5)
            if grasp.test_mode:
                dump_some()

flooder().start()
grasp.tprint("Flooding EX1 for ever")

###################################
# Listen Synchronize EX2
###################################

obj2.value = [1,"two",3]
err = grasp.listen_synchronize(asa_nonce, obj2)
grasp.tprint("Listening for synch requests for EX2", grasp.etext[err])


###################################
# Print obj_registry and flood cache
###################################

def dump_some():
    grasp.dump_all(partial=True)
    time.sleep(5)

dump_some()

####################################
# Support function for negotiator
####################################

def endit(snonce, r):
    grasp.tprint("Failed", r)
    err = grasp.end_negotiate(asa_nonce, snonce, False, reason=r)
    if err:
        grasp.tprint("end_negotiate error:",grasp.etext[err])

####################################
# Thread to handle an EX3 negotiation
####################################

class negotiator(threading.Thread):
    """Thread to negotiate obj3 as master"""
    def __init__(self, snonce, nobj):
        threading.Thread.__init__(self)
        self.snonce = snonce
        self.nobj = nobj

    def run(self):
        answer=self.nobj
        snonce=self.snonce
        
        try:
            answer.value=cbor.loads(answer.value)
            grasp.tprint("CBOR value decoded")
            _cbor = True
        except:
            _cbor = False
        grasp.ttprint("listened, answer",answer.name, answer.value)
        grasp.tprint("Got request for", answer.value[0], answer.value[1])
        if answer.dry:
            grasp.tprint("Dry run")
        result=True
        reason=None       
        
        if answer.value[0]!="NZD":
            endit(snonce, "Invalid currency")
        elif answer.value[1] > reserves/2:
            #other end wants too much, we need to negotiate
            proffer = int(reserves/2)
            step = 1
            concluded = False
            grasp.tprint("Starting negotiation")
            while not concluded:
                #proffer some resource
                grasp.tprint("Offering NZD",proffer)
                answer.value[1] = proffer
                if _cbor:
                    answer.value=cbor.dumps(answer.value)
                err,temp,answer = grasp.negotiate_step(asa_nonce, snonce, answer, 1000)
                grasp.ttprint("Step", step, "gave:", err, temp, answer)
                step += 1
                if (not err) and temp==None:
                    concluded = True
                    grasp.tprint("Negotiation succeeded")                 
                elif not err:
                    try:
                        answer.value=cbor.loads(answer.value)
                        grasp.tprint("CBOR value decoded")
                    except:
                        pass
                    grasp.tprint("Loop count", answer.loop_count,"request",answer.value[1])
                    #maybe wait (for no particular reason)
                    if _prng.randint(1,10)%2:                        
                        err1 = grasp.negotiate_wait(asa_nonce, snonce, wt)
                        grasp.tprint("Tried wait:", grasp.etext[err1])
                        time.sleep(10) # if wt<10000 this tests anomaly handling by the peer
                        grasp.tprint("Woke up")
                    if proffer < 0.6*reserves:
                        proffer += 10
                        if proffer > answer.value[1]:
                            proffer = answer.value[1]-1 #always be a little mean
                    else:
                        #we don't have enough resource, we will reject
                        result=False
                        #randomly choose English or Russian error message
                        if reserves%2:
                            reason="Insufficient funds"
                        else:
                            reason=u"Недостаточно средств"
                        endit(snonce, reason)
                        concluded = True
                else:    
                    #other end rejected or loop count exhausted
                    concluded=True
                    result=False
                    
                    if err==grasp.errors.loopExhausted:
                        # we need to signal the end
                        endit(snonce, grasp.etext[err])
                    elif err==grasp.errors.declined and answer!="":
                        grasp.tprint("Declined:",answer)
                    else:
                        grasp.tprint("Failed:",grasp.etext[err])
                        
                #end of negotiation loop
                pass
            #out of negotiation loop
        else: #we can accept the initially requested value
            grasp.tprint("Request accepted")
            err = grasp.end_negotiate(asa_nonce, snonce, True)
            if err:
                grasp.tprint("end_negotiate error:",grasp.etext[err])
        #end of a negotiating session


###################################
# Negotiate EX3 as listener for ever
###################################

obj3.value = ["NZD",0]
grasp.tprint("Ready to negotiate EX3 as listener")
grasp.ttprint("(Note: Cyrillic test case fails in a Windows console window, OK in IDLE window.)")

grasp.init_bubble_text("Briggs (old API)")

while True:
    #start of a negotiating session

    #create a random amount of resource and a random waiting time
    reserves = _prng.randint(100, 400)
    wt = _prng.randint(9000, 20000)
    grasp.tprint("Reserves: $",reserves, "Wait:",wt,"ms")
    
    #attempt to listen for negotiation
    err, snonce, answer = grasp.listen_negotiate(asa_nonce, obj3)
    if err:
        grasp.tprint("listen_negotiate error:",grasp.etext[err])
        time.sleep(5) #to calm things if there's a looping error
    else:
        #got a new negotiation request; kick off a separate negotiator
        #so that multiple requests can be handled in parallel
        negotiator(snonce, answer).start()

