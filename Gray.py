#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import graspi
import threading
import time
import cbor
import random

graspi.tprint("========================")
graspi.tprint("ASA Gray is starting up.")
graspi.tprint("========================")
graspi.tprint("Gray is a demonstration Autonomic Service Agent.")
graspi.tprint("It tests out several basic features of GRASP, and")
graspi.tprint("then runs indefinitely as one side of a negotiation.")
graspi.tprint("It acts as a client, asking for money.")
graspi.tprint("The sum requested is random for each negotiation,")
graspi.tprint("and some GRASP features are used at random.")
graspi.tprint("On Windows or Linux, there should be a nice window")
graspi.tprint("that displays the negotiation process.")
graspi.tprint("========================")

time.sleep(8) # so the user can read the text

_prng = random.SystemRandom() # best PRNG we can get

####################################
# Register ASA/objectives
####################################

err, asa_nonce = graspi.register_asa("Gray")
if not err:
    graspi.tprint("ASA Gray registered OK")
else:
    exit()

#This objective is for the flooding test
#so doesn't need to be registered
obj1 = graspi.objective("EX1")
obj1.loop_count = 4
obj1.synch = True

#This objective is for the synchronizing test
#so doesn't need to be registered
obj2 = graspi.objective("EX2")
obj2.loop_count = 4
obj2.synch = True

#This objective is for the negotiating test
obj3 = graspi.objective("EX3")
obj3.neg = True

err = graspi.register_obj(asa_nonce,obj3)
if not err:
    graspi.tprint("Objective EX3 registered OK")
else:
    exit()
    
###################################
# Try synchronizes
###################################

time.sleep(5)

graspi.tprint("Synchronization tests will start; some may fail.")

err, result = graspi.synchronize(asa_nonce, obj1, None, 5000)
if not err:
    graspi.tprint("Synchronized EX1", result.value)
else:
    graspi.tprint("Synch failed EX1", graspi.etext[err])

err, result = graspi.synchronize(asa_nonce, obj2, None, 5000)
if not err:
    graspi.tprint("Synchronized EX2", result.value)
else:
    graspi.tprint("Synch failed EX2", graspi.etext[err])    

  
#This should fail as test_obj was neither flooded or listened for.
test_obj = graspi.objective("Nonsense")
err, result = graspi.synchronize(asa_nonce, test_obj, None, 5000)
if not err:
    graspi.tprint("Synchronized Nonsense (should fail)", result.value)
else:
    graspi.tprint("Synch failed Nonsense (should fail)", graspi.etext[err])

#repeat
err, result = graspi.synchronize(asa_nonce, obj2, None, 5000)
if not err:
    graspi.tprint("Synchronized EX2", result.value)
else:
    graspi.tprint("Synch failed EX2", graspi.etext[err])  
    
err, result = graspi.synchronize(asa_nonce, obj1, None, 5000)
if not err:
    graspi.tprint("Synchronized EX1", result.value)
else:
    graspi.tprint("Synch failed EX1", graspi.etext[err])

           
###################################
# Print obj_registry and flood cache
###################################

def dump_some():
    graspi.dump_all(partial=True)
    time.sleep(5)

dump_some()

###################################
# Negotiate EX3 as initiator for ever
###################################

graspi.tprint("Ready to negotiate EX3 as requester")
graspi.ttprint("(Note: Cyrillic test case fails in a Windows console window, OK in IDLE window.)")
failct = 0
graspi.init_bubble_text("Gray")

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
    graspi.tprint("Asking for",obj3.value[0],iwant,"; dry run",obj3.dry)
    #discover a peer
    if failct > 3:
        failct = 0
        graspi.tprint("Flushing EX3 discovery")
##        err, result = graspi.synchronize(asa_nonce, obj1, None, 5000)
##        if not err:
##            graspi.tprint("Synchronized EX1", result.value)
##        else:
##            graspi.tprint("Synch failed EX1", graspi.etext[err])
##        if graspi.test_mode:
##            dump_some()
        _, ll = graspi.discover(asa_nonce, obj3, 1000, flush = True)
    else:
        _, ll = graspi.discover(asa_nonce, obj3, 1000)
    if ll==[]:
        graspi.tprint("Discovery failed")
        failct += 1
        continue
    graspi.ttprint("Discovered locator", ll[0].locator)
    #attempt to negotiate
    
    if _cbor:
        #CBORise the value
        obj3.value=cbor.dumps(obj3.value)
    
    err, snonce, answer, reason = graspi.request_negotiate(asa_nonce, obj3, ll[0], None)
    if err:
        if err==graspi.errors.declined and reason!="":
            _e = reason
        else:
            _e = graspi.etext[err]
        graspi.tprint("request_negotiate error:", _e)
        failct += 1
        graspi.tprint("Fail count", failct)
        time.sleep(5) #to calm things if there's a looping error
    elif (not err) and snonce:
        graspi.ttprint("requested, session_nonce:",snonce,"answer",answer)
        if _cbor:
            try:
                answer.value = cbor.loads(answer.value)
            except:
                pass
        graspi.tprint("Peer offered",answer.value[1])
        proffer = int(0.9*iwant)
        step = 1
        if answer.value[1]<proffer: 
            #need to negotiate
            answer.value[1] = proffer
            concluded = False
            while not concluded:
                graspi.tprint("Asking for", proffer)
                if _cbor:
                    #CBORise the value
                    answer.value=cbor.dumps(answer.value)                
                err,temp,answer,reason = graspi.negotiate_step(asa_nonce, snonce, answer, 1000)
                graspi.ttprint("Loop count", step, "gave:", err, temp, answer, reason)
                if _cbor and (not err):
                    try:
                        answer.value = cbor.loads(answer.value)
                    except:
                        pass
                if (not err) and temp==None:
                    graspi.tprint("Negotiation succeeded", answer.value)
                    concluded = True
                elif not err:
                    graspi.tprint("Loop count", answer.loop_count, "offered", answer.value[1])
                    step += 1
                    proffer = int(0.9*proffer)
                    if answer.value[1] >= proffer:
                        #acceptable answer
                        err = graspi.end_negotiate(asa_nonce, snonce, True)
                        if not err:
                            graspi.tprint("Negotiation succeeded", answer.value)
                        else:
                            graspi.tprint("end_negotiate error:",graspi.etext[err])
                        concluded = True
                    if (not concluded) and (proffer < limit):
                        #not acceptable
                        graspi.tprint("Rejecting unacceptable offer")
                        err = graspi.end_negotiate(asa_nonce, snonce, False, reason="You are mean!")
                        if err:
                            graspi.tprint("end_negotiate error:",graspi.etext[err])
                        concluded = True
                        break
                    answer.value[1] = proffer
                else:    
                    #other end rejected
                    if err==graspi.errors.declined and reason!="":
                        _e = reason
                    else:
                        _e = graspi.etext[err]
                    graspi.tprint("Peer reject:",_e)
                    concluded = True
                    break
                #end of inner loop
        else: #acceptable answer
            err = graspi.end_negotiate(asa_nonce, snonce, True)
            if not err:
                graspi.tprint("Negotiation succeeded", answer.value)
            else:
                graspi.tprint("end_negotiate error:",graspi.etext[err])
    else:
        #acceptable answer first time
        if _cbor:
            try:
                answer.value = cbor.loads(answer.value)
            except:
                pass
        graspi.tprint("Negotiation succeeded", answer.value)
 
    #end of a negotiating session
    time.sleep(5) #to keep things calm...
    if graspi.grasp.test_mode:
        dump_some()
    #try the flooded objective again
    err, result = graspi.synchronize(asa_nonce, obj1, None, 5000)
    if not err:
        graspi.tprint("Synchronized EX1", result.value)
    else:
        graspi.tprint("Synch failed EX1", graspi.etext[err])
    #and try it differently
    err, results = graspi.get_flood(asa_nonce, obj1)
    if not err:
        for x in results:
            graspi.tprint("Flooded EX1 from", x.source.locator, "=", x.objective.value)
    else:
        graspi.tprint("get_flood failed EX1", graspi.etext[err])    
