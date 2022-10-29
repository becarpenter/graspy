#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import grasp
import threading
import time
import cbor
import random

grasp.tprint("========================")
grasp.tprint("ASA Gray is starting up (old API).")
grasp.tprint("========================")
grasp.tprint("Gray is a demonstration Autonomic Service Agent.")
grasp.tprint("It tests out several basic features of GRASP, and")
grasp.tprint("then runs indefinitely as one side of a negotiation.")
grasp.tprint("It acts as a client, asking for money.")
grasp.tprint("The sum requested is random for each negotiation,")
grasp.tprint("and some GRASP features are used at random.")
grasp.tprint("On Windows or Linux, there should be a nice window")
grasp.tprint("that displays the negotiation process.")
grasp.tprint("========================")

time.sleep(8) # so the user can read the text
_prng = random.SystemRandom() # best PRNG we can get

####################################
# Register ASA/objectives
####################################

err, asa_nonce = grasp.register_asa("Gray")
if not err:
    grasp.tprint("ASA Gray registered OK")
else:
    exit()

#This objective is for the flooding test
#so doesn't need to be registered
obj1 = grasp.objective("EX1")
obj1.loop_count = 4
obj1.synch = True

#This objective is for the synchronizing test
#so doesn't need to be registered
obj2 = grasp.objective("EX2")
obj2.loop_count = 4
obj2.synch = True

#This objective is for the negotiating test
obj3 = grasp.objective("EX3")
obj3.neg = True

err = grasp.register_obj(asa_nonce,obj3)
if not err:
    grasp.tprint("Objective EX3 registered OK")
else:
    exit()
    
###################################
# Try synchronizes
###################################

time.sleep(5)

grasp.tprint("Synchronization tests will start; some may fail.")

err, result = grasp.synchronize(asa_nonce, obj1, None, 5000)
if not err:
    grasp.tprint("Synchronized EX1", result.value)
else:
    grasp.tprint("Synch failed EX1", grasp.etext[err])

err, result = grasp.synchronize(asa_nonce, obj2, None, 5000)
if not err:
    grasp.tprint("Synchronized EX2", result.value)
else:
    grasp.tprint("Synch failed EX2", grasp.etext[err])    

  
#This should fail as test_obj was neither flooded or listened for.
test_obj = grasp.objective("Nonsense")
err, result = grasp.synchronize(asa_nonce, test_obj, None, 5000)
if not err:
    grasp.tprint("Synchronized Nonsense (should fail)", result.value)
else:
    grasp.tprint("Synch failed Nonsense (should fail)", grasp.etext[err])

#repeat
err, result = grasp.synchronize(asa_nonce, obj2, None, 5000)
if not err:
    grasp.tprint("Synchronized EX2", result.value)
else:
    grasp.tprint("Synch failed EX2", grasp.etext[err])  
    
err, result = grasp.synchronize(asa_nonce, obj1, None, 5000)
if not err:
    grasp.tprint("Synchronized EX1", result.value)
else:
    grasp.tprint("Synch failed EX1", grasp.etext[err])

           
###################################
# Print obj_registry and flood cache
###################################

def dump_some():
    grasp.dump_all(partial=True)
    time.sleep(5)

dump_some()

###################################
# Negotiate EX3 as initiator for ever
###################################

grasp.tprint("Ready to negotiate EX3 as requester")
grasp.ttprint("(Note: Cyrillic test case fails in a Windows console window, OK in IDLE window.)")
failct = 0
grasp.init_bubble_text("Gray (old API)")

while True:
    #start of a negotiating session
    iwant = _prng.randint(10, 500) # random requested value
    limit = int(0.7*iwant)
    obj3.value = ["NZD",iwant]
    obj3.loop_count = _prng.randint(4, 20) # random loop count

    #if not iwant%5:
    if iwant & 4:
        obj3.dry = True # signal a dry run at random
    else:
        obj3.dry = False

    #if not iwant%6:
    if iwant & 8:
        _cbor = True # use Tag24 at random
    else:
        _cbor = False    

    if not iwant%7:
        obj3.value[0] = "USD"  # random error for testing purposes
    grasp.tprint("Asking for",obj3.value[0],iwant,"; dry run",obj3.dry)
    #discover a peer
    if failct > 3:
        failct = 0
        grasp.tprint("Flushing EX3 discovery")
##        err, result = grasp.synchronize(asa_nonce, obj1, None, 5000)
##        if not err:
##            grasp.tprint("Synchronized EX1", result.value)
##        else:
##            grasp.tprint("Synch failed EX1", grasp.etext[err])
##        if grasp.test_mode:
##            dump_some()
        _, ll = grasp.discover(asa_nonce, obj3, 1000, flush = True)
    else:
        _, ll = grasp.discover(asa_nonce, obj3, 1000)
    if ll==[]:
        grasp.tprint("Discovery failed")
        failct += 1
        continue
    grasp.ttprint("Discovered locator", ll[0].locator)
    #attempt to negotiate
    
    if _cbor:
        #CBORise the value
        obj3.value=cbor.dumps(obj3.value)
    
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
        if _cbor:
            try:
                answer.value = cbor.loads(answer.value)
            except:
                pass
        grasp.tprint("Peer offered",answer.value[1])
        proffer = int(0.9*iwant)
        step = 1
        if answer.value[1]<proffer: 
            #need to negotiate
            answer.value[1] = proffer
            concluded = False
            while not concluded:
                grasp.tprint("Asking for", proffer)
                if _cbor:
                    #CBORise the value
                    answer.value=cbor.dumps(answer.value)                
                err,temp,answer = grasp.negotiate_step(asa_nonce, snonce, answer, 1000)
                grasp.ttprint("Loop count", step, "gave:", err, temp, answer)
                if _cbor and (not err):
                    try:
                        answer.value = cbor.loads(answer.value)
                    except:
                        pass
                if (not err) and temp==None:
                    grasp.tprint("Negotiation succeeded", answer.value)
                    concluded = True
                elif not err:
                    grasp.tprint("Loop count", answer.loop_count, "offered", answer.value[1])
                    step += 1
                    proffer = int(0.9*proffer)
                    if answer.value[1] >= proffer:
                        #acceptable answer
                        err = grasp.end_negotiate(asa_nonce, snonce, True)
                        if not err:
                            grasp.tprint("Negotiation succeeded", answer.value)
                        else:
                            grasp.tprint("end_negotiate error:",grasp.etext[err])
                        concluded = True
                    if (not concluded) and (proffer < limit):
                        #not acceptable
                        grasp.tprint("Rejecting unacceptable offer")
                        err = grasp.end_negotiate(asa_nonce, snonce, False, reason="You are mean!")
                        if err:
                            grasp.tprint("end_negotiate error:",grasp.etext[err])
                        concluded = True
                        break
                    answer.value[1] = proffer
                else:    
                    #other end rejected
                    if err==grasp.errors.declined and answer!="":
                        _e = answer
                    else:
                        _e = grasp.etext[err]
                    grasp.tprint("Peer reject:",_e)
                    concluded = True
                    break
                #end of inner loop
        else: #acceptable answer
            err = grasp.end_negotiate(asa_nonce, snonce, True)
            if not err:
                grasp.tprint("Negotiation succeeded", answer.value)
            else:
                grasp.tprint("end_negotiate error:",grasp.etext[err])
    else:
        #acceptable answer first time
        if _cbor:
            try:
                answer.value = cbor.loads(answer.value)
            except:
                pass
        grasp.tprint("Negotiation succeeded", answer.value)
 
    #end of a negotiating session
    time.sleep(5) #to keep things calm...
    if grasp.test_mode:
        dump_some()
    #try the flooded objective again
    err, result = grasp.synchronize(asa_nonce, obj1, None, 5000)
    if not err:
        grasp.tprint("Synchronized EX1", result.value)
    else:
        grasp.tprint("Synch failed EX1", grasp.etext[err])
    #and try it differently
    err, results = grasp.get_flood(asa_nonce, obj1)
    if not err:
        for x in results:
            grasp.tprint("Flooded EX1 from", x.source.locator, "=", x.objective.value)
    else:
        grasp.tprint("get_flood failed EX1", grasp.etext[err])    
