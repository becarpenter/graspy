#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Various tests for the RFC API for GRASP. This code is
intended to exercise code paths. It is not an example of
elegant coding practice and I advise against copying it.
You need to invoke ASAtest() to make it do anything."""

import graspi
import threading
import time
import cbor

class testASA(threading.Thread):
    """Bits and pieces of code to test things by pretending to be an ASA"""
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        time.sleep(1) # avoid printing glitch
        graspi.tprint("WARNING: you can't run this test suite more than once without restarting the Python context; it leaves GRASP data structures dirty!\n")
        graspi.skip_dialogue(testing=True, selfing=True, diagnosing=True)
        time.sleep(1) # just to avoid mixed up print output

####################################
# Test code: register ASA/objective#
####################################

        test_obj = graspi.objective("EX1")
        test_obj.loop_count = 2
        test_obj.synch=True
        err,test_nonce = graspi.register_asa("ASA-1")
        if not err:
            err = graspi.register_obj(test_nonce,test_obj,ttl=10000)
            if not err:
                graspi.tprint("ASA-1 and EX1 Registered OK")


####################################
# Test code: discover EX1          #
####################################


        err, test_ll = graspi.discover(test_nonce, test_obj, 10000)
        if len(test_ll)>0:
            graspi.tprint("EX1 discovery result", test_ll[0].locator)
        else:
            graspi.tprint("No EX1 discovery response")

####################################
# Test code: register and discover #
# Boot ASA/objective               #
####################################


        err, boot_nonce = graspi.register_asa("Boot")
        if err:
            #we've got a problem...
            raise RuntimeError("Can't register Boot as ASA")

        boot_obj = graspi.objective("Boot")
        boot_obj.loop_count = 2
        boot_obj.synch = True
        err = graspi.register_obj(boot_nonce, boot_obj,discoverable=True)

        if err:
            #we've got a different problem...
            raise RuntimeError("Can't register Boot objective")
        
        for i in range(3):
            #test discovery 3 times, including artificial Divert
            graspi.tprint("Test ASA: grasp._test_divert",graspi.grasp._test_divert)
            err, boot_ll = graspi.discover(boot_nonce, boot_obj, 5000)
            if len(boot_ll)>0:
                graspi.tprint("Boot discovery result", boot_ll[0].locator)
                graspi.grasp._test_divert = True
            else:
                graspi.tprint("No Boot discovery response")
            time.sleep(5)
        graspi.grasp._test_divert = False

####################################
# Test code: send Flood messages
####################################

        obj1 = graspi.objective("Money")
        obj1.synch = True
        obj1.loop_count=2
        err = graspi.register_obj(test_nonce,obj1)
        obj1.value = [100,"NZD"]


        obj2 = graspi.objective("Bling")
        obj2.synch = True
        obj2.loop_count=2
        err = graspi.register_obj(test_nonce,obj2)
        obj2.value = ["Diamonds", "Rubies"]
        err = graspi.register_obj(test_nonce,obj2)
        if err:
            graspi.tprint(graspi.etext[err])
            
        obj3 = graspi.objective("Intent.PrefixManager")
        obj3.synch = True
        obj3.loop_count=2
        err = graspi.register_obj(test_nonce,obj3)
        #obj3.value = '{"autonomic_intent":[{"model_version": "1.0"},{"intent_type": "Network management"},{"autonomic_domain": "Customer_X_intranet"},{"intent_name": "Prefix management"},{"intent_version": 73},{"Timestamp": "20150606 00:00:00"},{"Lifetime": "Permanent"},{"signature":"XXXXXXXXXXXXXXXXXXX"},{"content":[{"role": [{"role_name": "RSG"},{"role_characteristic":[{"prefix_length":"34"}]}]},{"role": [{"role_name": "ASG"},{"role_characteristic":[{"prefix_length": "44"}]}]},{"role": [{"role_name": "CSG"},{"role_characteristic":[{"prefix_length": "56"}]}]}]}]}'

        #obj3.value = '{"autonomic_intent dummy text"}'
        #obj3.value = bytes.fromhex('48deadbeefdeadbeef') #dummy CBOR
        obj3.value = cbor.dumps(["Some","embedded","CBOR",[1,2,3]])

        graspi.flood(test_nonce, 0, [graspi.tagged_objective(obj1,None),
                    graspi.tagged_objective(obj2,None),
                    graspi.tagged_objective(obj3,None)])

###################################
# Test code: Listen Synchronize as from Boot ASA
###################################

        boot_obj.value = [1,"two",3]
        boot_obj.synch = True
        err = graspi.listen_synchronize(boot_nonce, boot_obj)
        graspi.tprint("Listen synch", graspi.etext[err])
        graspi.tprint(graspi.grasp._obj_registry[1].objective.name,
                      "value", graspi.grasp._obj_registry[1].objective.value)

###################################
# Test code: call Synchronize as from EX1
###################################
        time.sleep(5)

        err, result = graspi.synchronize(test_nonce, obj2, None, 5000)
        if not err:
            graspi.tprint("Flooded synch obj2", result.value)
        else:
            graspi.tprint("Synch fail obj2", graspi.etext[err])

        err, result = graspi.synchronize(test_nonce, obj3, None, 5000)
        if not err:
            graspi.tprint("Flooded synch obj3", result.value)
        else:
            graspi.tprint("Synch fail obj3", graspi.etext[err])    

  
        #this should fail as test_obj was neither flooded or listened for.
        err, result = graspi.synchronize(test_nonce, test_obj, None, 5000)
        if not err:
            graspi.tprint("Synch test_obj (should fail)", result.value)
        else:
            graspi.tprint("Synch fail test_obj (should fail)", graspi.etext[err])

        boot2_obj = graspi.objective("Boot")
        boot2_obj.synch = True

        err, result = graspi.synchronize(test_nonce, boot2_obj, None, 5000)
        if not err:
            graspi.tprint("Synch boot2_obj", result.name, result.value)
        else:
            graspi.tprint("Synch fail boot2_obj", graspi.etext[err])


###################################
# Test code: print obj_registry
# and flood cache
###################################

        graspi.tprint("Objective registry contents:")         
        for x in graspi.grasp._obj_registry:
            o= x.objective
            graspi.tprint(o.name,"ASA:",x.asa_id,"Listen:",x.listening,"Neg:",o.neg,
                   "Synch:",o.synch,"Count:",o.loop_count,"Value:",o.value)
        graspi.tprint("Flood cache contents:")            
        for x in graspi.grasp._flood_cache:
            graspi.tprint(x.objective.name,"count:",x.objective.loop_count,"value:",
                         x.objective.value,"source:",x.source)
        time.sleep(5)

###################################
# Test code: check flood cache for Tag 24 case
###################################

        flobj = graspi.objective("Intent.PrefixManager")
        flobj.synch = True
        err, tobs = graspi.get_flood(test_nonce,flobj)
        if not err:
            for x in tobs:
                try:
                    graspi.tprint("Flooded CBOR",x.objective.name,cbor.loads(x.objective.value))
                except:
                    graspi.tprint("Flooded raw",x.objective.name,x.objective.value)

###################################
# Test code: deregister and then
# attempt synch            
###################################

        err = graspi.deregister_obj(boot_nonce, boot_obj)
        if not err:
            graspi.tprint("Deregistered Boot",)
        else:
            graspi.tprint("Deregister failure",graspi.etext[err])
            
        err, result = graspi.synchronize(test_nonce, boot2_obj, None, 5000)
        if not err:
            graspi.tprint("Synch boot2_obj (should fail)", result.name, result.value)
        else:
            graspi.tprint("Synch fail boot2_obj (should fail)", graspi.etext[err])

###################################
# Test code: start in-host negotiate test
###################################
        cheat_nonce = None
        Neg1().start()
        time.sleep(10)
        Neg2().start()


#####################################
# Test code: 
# test deregistering an ASA,
# and exit the thread
#####################################

        graspi.deregister_asa(test_nonce,"ASA-1")
        graspi.tprint("Exiting ASA test thread")

###################################
# Test code: first negotiator
###################################

class Neg1(threading.Thread):
    """First test negotiator"""
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        global cheat_nonce
        reserves = graspi.grasp._prng.randint(100, 400)
        wt = graspi.grasp._prng.randint(15000, 40000)
        graspi.tprint("Reserves: $",reserves, "wait:",wt)
        err, asa_nonce=graspi.register_asa("Neg1") #assume it worked
        obj = graspi.objective("EX2")
        obj.neg = True
        #obj.loop_count = 2  #for testing purposes
        graspi.register_obj(asa_nonce, obj) #assume it worked
        cheat_nonce = asa_nonce #pass the nonce to the other negotiator!
        #attempt to listen
        err, snonce, answer = graspi.listen_negotiate(asa_nonce, obj)
        if err:
            graspi.tprint("listen_negotiate error:",graspi.etext[err])
        else:
            graspi.tprint("listened, answer",answer.name, answer.value)
            graspi.tprint("Source was", snonce.id_source)
            result=True
            reason=None
            concluded=False
            if answer.value[0]!="NZD":
                result=False
                reason="Invalid currency"
            elif answer.value[1] > reserves/2:
                answer.value = ["NZD",int(reserves/2)]
                err,temp,answer2,reason2 = graspi.negotiate_step(asa_nonce, snonce, answer, 1000)
                graspi.tprint("Step1 gave:", err, temp, answer2, reason2)
                if (not err) and (not temp):
                    concluded=True
                    graspi.tprint("Negotiation succeeded", answer2.value)                 
                elif not err:
                    err1 = graspi.negotiate_wait(asa_nonce, snonce, wt)
                    graspi.tprint("Tried wait:", graspi.etext[err1])
                    time.sleep(20) #note - if wt<20000 this tests anomaly handling
                    graspi.tprint("Woke up")
                    answer2.value = ["NZD",int(0.75*reserves)]
                    err2,temp,answer3,reason3 = graspi.negotiate_step(asa_nonce, snonce, answer2, 1000)
                    graspi.tprint("Step2 gave:", err2, temp, answer3, reason3)
                    if (not err2) and (not temp):
                        concluded=True
                        graspi.tprint("Negotiation succeeded", answer3.value)
                    elif not err2:
                        result=False
                        if reserves%2:
                            reason="Insufficient funds"
                        else:
                            reason=u"Недостаточно средств"
                    else:
                        #other end rejected
                        concluded=True
                        graspi.tprint("Peer reject2:",reason3)                    
                else:    
                    #other end rejected
                    concluded=True
                    graspi.tprint("Peer reject1:",reason2)
            else: #can accept the requested value
                pass
            if not concluded:
                err = graspi.end_negotiate(asa_nonce, snonce, result, reason=reason)
                if err:
                    graspi.tprint("end_negotiate error:",graspi.etext[err])
        graspi.tprint("Exit")

###################################
# Test code: second negotiator
###################################

class Neg2(threading.Thread):
    """Second test negotiator"""
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        global cheat_nonce
        
        
        iwant = graspi.grasp._prng.randint(10, 500)
        graspi.tprint("Asking for $",iwant)
        err, asa_nonce2=graspi.register_asa("Neg2") #assume it worked
        obj = graspi.objective("EX2")
        obj.neg = True
        #obj.loop_count = 2  #for testing purposes
        while cheat_nonce == None:
            time.sleep(1) #we should exit after neg1 has registered the objective
        asa_nonce = cheat_nonce #now we can pretend to own the objective
        graspi.tprint("Got nonce", asa_nonce)
        err, ll = graspi.discover(asa_nonce, obj, 5000)
        if ll==[]:
            graspi.tprint("Discovery failed: exit")
            return
        graspi.tprint("Discovered locator", ll[0].locator)
        #attempt to negotiate
        obj.value = ["NZD",iwant]
        if not iwant%7:
            obj.value = ["USD",iwant]  # for testing purposes
        err,snonce,answer,reason = graspi.request_negotiate(asa_nonce, obj, ll[0], None)
        if err:
            if err==graspi.errors.declined and reason!="":
                _t = reason
            else:
                _t = graspi.etext[err]
            graspi.tprint("req_negotiate error:",_t)
        elif (not err) and snonce:
            graspi.tprint("requested, session_nonce:",snonce,"answer",answer)
            if answer.value[1]<0.75*iwant: 
                answer.value[1] = int(0.75*iwant)
                err,temp,answer2,reason2 = graspi.negotiate_step(asa_nonce, snonce, answer, 1000)
                graspi.tprint("Step1 gave:", err, temp, answer2,reason2)
                if (not err) and (not temp):
                    graspi.tprint("Negotiation succeeded", answer.value)
                elif not err:
                    #not acceptable, try one more time
                    answer2.value[1] = int(0.6*iwant)
                    #at random, throw an invalid format of message
                    if not iwant%3:
                        graspi.tprint("Trying badmess")
                        graspi._make_badmess = True
                    err,temp,answer3,reason3 = graspi.negotiate_step(asa_nonce, snonce, answer2, 1000)
                    graspi.tprint("Step2 gave:", err, temp, answer3,reason3)
                    if (not err) and (not temp):
                        graspi.tprint("Negotiation succeeded", answer3.value)
                    elif (not err):
                        #not acceptable
                        err = graspi.end_negotiate(asa_nonce, snonce, False, reason="You are mean!")
                        if err:
                            graspi.tprint("end_negotiate error:",graspi.etext[err])
                    else:
                        #other end rejected
                        graspi.tprint("Peer reject:",reason)    
                else:    
                    #other end rejected
                    graspi.tprint("Peer reject:",reason)                         
            else: #acceptable answer
                err = graspi.end_negotiate(asa_nonce, snonce, True)
                if not err:
                    graspi.tprint("Negotiation succeeded", answer.value)
                else:
                    graspi.tprint("end_negotiate error:",graspi.etext[err])
        else: #acceptable answer first time
            graspi.tprint("Negotiation succeeded", answer.value)
                
            
        graspi.tprint("Exit")

def ASAtest():
    """Convenience function for manual test runs"""
    testASA().start()

#### end of test ASA stuff #########  
