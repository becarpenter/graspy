#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
_old_API = False
try:
    import graspi
except:
    print("Cannot find the RFC API module graspi.py.")
    print("Will run with only the basic grasp.py module.")
    _old_API = True
    try:
        import grasp as graspi
    except:
        print("Cannot import grasp.py")
        time.sleep(10)
        exit()
import threading
import datetime
import cbor
import random

####################################
# Flood EX1 repeatedly
####################################

class flooder(threading.Thread):
    """Thread to flood EX1 repeatedly"""
    global keep_going
    def __init__(self):
        threading.Thread.__init__(self, daemon=True)

    def run(self):
        while keep_going:
            time.sleep(60)
            obj1.value = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC from Briggs")
            err = graspi.flood(asa_handle, 59000, [graspi.tagged_objective(obj1,None)])
            if err:
                graspi.tprint("Flood failure:",graspi.etext[err])
            time.sleep(5)
            if _old_API:
                if graspi.test_mode:
                    dump_some()
            else:
                if graspi.grasp.test_mode:
                    dump_some()
        graspi.tprint("Flooder exiting")


###################################
# Print obj_registry and flood cache
###################################

def dump_some():
    graspi.dump_all(partial=True)
    time.sleep(5)


####################################
# Support function for negotiator
####################################

def endit(shandle, r):
    graspi.tprint("Failed", r)
    err = graspi.end_negotiate(asa_handle, shandle, False, reason=r)
    if err:
        graspi.tprint("end_negotiate error:",graspi.etext[err])

####################################
# Thread to handle an EX3 negotiation
####################################

class negotiator(threading.Thread):
    """Thread to negotiate obj3 as master"""
    global keep_going, _prng, reserves, asa_handle
    def __init__(self, shandle, nobj):
        threading.Thread.__init__(self, daemon=True)
        self.shandle = shandle
        self.nobj = nobj

    def run(self):
        answer=self.nobj
        shandle=self.shandle
        
        try:
            answer.value=cbor.loads(answer.value)
            graspi.tprint("CBOR value decoded")
            _cbor = True
        except:
            _cbor = False
        graspi.ttprint("listened, answer",answer.name, answer.value)
        graspi.tprint("Got request for", answer.value[0], answer.value[1])
        if answer.dry:
            graspi.tprint("Dry run")
        result=True
        reason=None       
        
        if answer.value[0]!="NZD":
            endit(shandle, "Invalid currency")
        elif answer.value[1] > reserves/2:
            #other end wants too much, we need to negotiate
            proffer = int(reserves/2)
            step = 1
            concluded = False
            graspi.tprint("Starting negotiation")
            while not concluded:
                #proffer some resource
                graspi.tprint("Offering NZD",proffer)
                answer.value[1] = proffer
                if _cbor:
                    answer.value=cbor.dumps(answer.value)
                _r = graspi.negotiate_step(asa_handle, shandle, answer, 1000)
                if _old_API:
                    err,temp,answer = _r
                    reason = answer
                else:
                    err,temp,answer,reason = _r
                graspi.ttprint("Step", step, "gave:", err, temp, answer,reason)
                step += 1
                if (not err) and temp==None:
                    concluded = True
                    graspi.tprint("Negotiation succeeded")                 
                elif not err:
                    try:
                        answer.value=cbor.loads(answer.value)
                        graspi.tprint("CBOR value decoded")
                    except:
                        pass
                    graspi.tprint("Loop count", answer.loop_count,"request",answer.value[1])
                    #maybe wait (for no particular reason)
                    if _prng.randint(1,10)%2:                        
                        err1 = graspi.negotiate_wait(asa_handle, shandle, wt)
                        graspi.tprint("Tried wait:", graspi.etext[err1])
                        time.sleep(10) # if wt<10000 this tests anomaly handling by the peer
                        graspi.tprint("Woke up")
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
                        endit(shandle, reason)
                        concluded = True
                else:    
                    #other end rejected or loop count exhausted
                    concluded=True
                    result=False
                    
                    if err==graspi.errors.loopExhausted:
                        # we need to signal the end
                        endit(shandle, graspi.etext[err])
                    elif err==graspi.errors.declined and reason!="":
                        graspi.tprint("Declined:",reason)
                    else:
                        graspi.tprint("Failed:",graspi.etext[err])
                        
                #end of negotiation loop
                pass
            #out of negotiation loop
        else: #we can accept the initially requested value
            graspi.tprint("Request accepted")
            err = graspi.end_negotiate(asa_handle, shandle, True)
            if err:
                graspi.tprint("end_negotiate error:",graspi.etext[err])
        #end of a negotiating session

######################
# Main code starts
######################                

global keep_going, _prng, reserves, asa_handle

try:
    graspi.checkrun
except:
    #not running under ASA loader
    graspi.tprint("==========================")
    graspi.tprint("ASA Briggs is starting up.")
    graspi.tprint("==========================")
    graspi.tprint("Briggs is a demonstration Autonomic Service Agent.")
    graspi.tprint("It tests out several basic features of GRASP, and")
    graspi.tprint("then runs indefinitely as one side of a negotiation.")
    graspi.tprint("It acts as the banker, giving out money, and can")
    graspi.tprint("handle multiple overlapping negotiations.")
    graspi.tprint("The sum available is random for each negotiation,")
    graspi.tprint("and the negotiation timeout is changed at random.")
    graspi.tprint("On Windows or Linux, there should be a nice window")
    graspi.tprint("that displays the negotiation process.")
    graspi.tprint("==========================")

    time.sleep(8) # so the user can read the text
    
_prng = random.SystemRandom() # best PRNG we can get
keep_going = True

####################################
# Register ASA/objectives
####################################

err,asa_handle = graspi.register_asa("Briggs")
if not err:
    graspi.tprint("ASA Briggs registered OK")
else:
    graspi.tprint("Cannot register ASA:", graspi.etext[err])
    keep_going = False
    
obj1 = graspi.objective("EX1")
obj1.loop_count = 4
obj1.synch = True

err = graspi.register_obj(asa_handle,obj1)
if not err:
    graspi.tprint("Objective EX1 registered OK")
else:
    graspi.tprint("Cannot register objective:", graspi.etext[err])
    keep_going = False

obj2 = graspi.objective("EX2")
obj2.loop_count = 4
obj2.synch = True

err = graspi.register_obj(asa_handle,obj2,rapid=True)
if not err:
    graspi.tprint("Objective EX2 registered OK")   
else:
    graspi.tprint("Cannot register objective:", graspi.etext[err])
    keep_going = False

obj3 = graspi.objective("EX3")
obj3.neg = True
obj3.dry = True

err = graspi.register_obj(asa_handle,obj3,overlap=True)
if not err:
    graspi.tprint("Objective EX3 registered OK") 
else:
    graspi.tprint("Cannot register objective:", graspi.etext[err])
    keep_going = False

dump_some()

flooder().start()
graspi.tprint("Flooding EX1 for ever")

###################################
# Listen Synchronize EX2
###################################

obj2.value = [1,"two",3]
err = graspi.listen_synchronize(asa_handle, obj2)
graspi.tprint("Listening for synch requests for EX2", graspi.etext[err])


###################################
# Negotiate EX3 as listener for ever
###################################

obj3.value = ["NZD",0]
graspi.tprint("Ready to negotiate EX3 as listener")
graspi.ttprint("(Note: Cyrillic test case fails in a Windows console window, OK in IDLE window.)")

graspi.init_bubble_text("Briggs")

while keep_going:
    #start of a negotiating session

    #create a random amount of resource and a random waiting time
    reserves = _prng.randint(100, 400)
    wt = _prng.randint(9000, 20000)
    graspi.tprint("Reserves: $",reserves, "Wait:",wt,"ms")
    ##if not reserves%7:
    ##    0/0 #random crash for testing
    
    #attempt to listen for negotiation
    err, shandle, answer = graspi.listen_negotiate(asa_handle, obj3)
    if err:
        graspi.tprint("listen_negotiate error:",graspi.etext[err])
        time.sleep(5) #to calm things if there's a looping error
    else:
        #got a new negotiation request; kick off a separate negotiator
        #so that multiple requests can be handled in parallel
        negotiator(shandle, answer).start()
    try:
        if not graspi.checkrun(asa_handle, "Briggs"):
            keep_going = False
    except:
        #not running under ASA loader
        pass
graspi.deregister_asa(asa_handle, "Briggs")
graspi.tprint("ASA exiting")


