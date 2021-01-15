#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Various tests for GRASP. This code is intended to exercise
code paths. It is not an example of elegant coding practice
and I advise against copying it. You need to invoke ASAtest()
to make it do anything."""

import grasp
import threading
import time
import cbor

class testASA(threading.Thread):
    """Bits and pieces of code to test things by pretending to be an ASA"""
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        time.sleep(1) # avoid printing glitch
        grasp.tprint("WARNING: you can't run this test suite more than once without restarting the Python context; it leaves GRASP data structures dirty!\n")
        grasp.skip_dialogue(testing=True, selfing=True, diagnosing=True)
        time.sleep(1) # just to avoid mixed up print output

####################################
# Test code: register ASA/objective#
####################################

        test_obj = grasp.objective("EX1")
        test_obj.loop_count = 2
        test_obj.synch=True
        err,test_nonce = grasp.register_asa("ASA-1")
        if not err:
            err = grasp.register_obj(test_nonce,test_obj,ttl=10000)
            if not err:
                grasp.tprint("ASA-1 and EX1 Registered OK")


####################################
# Test code: discover EX1          #
####################################


        err, test_ll = grasp.discover(test_nonce, test_obj, 10000)
        if len(test_ll)>0:
            grasp.tprint("EX1 discovery result", test_ll[0].locator)
        else:
            grasp.tprint("No EX1 discovery response")

####################################
# Test code: register and discover #
# Boot ASA/objective               #
####################################


        err, boot_nonce = grasp.register_asa("Boot")
        if err:
            #we've got a problem...
            raise RuntimeError("Can't register Boot as ASA")

        boot_obj = grasp.objective("Boot")
        boot_obj.loop_count = 2
        boot_obj.synch = True
        err = grasp.register_obj(boot_nonce, boot_obj,discoverable=True)

        if err:
            #we've got a different problem...
            raise RuntimeError("Can't register Boot objective")
        
        for i in range(3):
            #test discovery 3 times, including artificial Divert
            grasp.tprint("Test ASA: grasp._test_divert",grasp._test_divert)
            err, boot_ll = grasp.discover(boot_nonce, boot_obj, 5000)
            if len(boot_ll)>0:
                grasp.tprint("Boot discovery result", boot_ll[0].locator)
                grasp._test_divert = True
            else:
                grasp.tprint("No Boot discovery response")
            time.sleep(5)
        grasp._test_divert = False

####################################
# Test code: send Flood messages
####################################

        obj1 = grasp.objective("Money")
        obj1.synch = True
        obj1.loop_count=2
        err = grasp.register_obj(test_nonce,obj1)
        obj1.value = [100,"NZD"]


        obj2 = grasp.objective("Bling")
        obj2.synch = True
        obj2.loop_count=2
        err = grasp.register_obj(test_nonce,obj2)
        obj2.value = ["Diamonds", "Rubies"]
        err = grasp.register_obj(test_nonce,obj2)
        if err:
            grasp.tprint(grasp.etext[err])
            
        obj3 = grasp.objective("Intent.PrefixManager")
        obj3.synch = True
        obj3.loop_count=2
        err = grasp.register_obj(test_nonce,obj3)
        #obj3.value = '{"autonomic_intent":[{"model_version": "1.0"},{"intent_type": "Network management"},{"autonomic_domain": "Customer_X_intranet"},{"intent_name": "Prefix management"},{"intent_version": 73},{"Timestamp": "20150606 00:00:00"},{"Lifetime": "Permanent"},{"signature":"XXXXXXXXXXXXXXXXXXX"},{"content":[{"role": [{"role_name": "RSG"},{"role_characteristic":[{"prefix_length":"34"}]}]},{"role": [{"role_name": "ASG"},{"role_characteristic":[{"prefix_length": "44"}]}]},{"role": [{"role_name": "CSG"},{"role_characteristic":[{"prefix_length": "56"}]}]}]}]}'

        #obj3.value = '{"autonomic_intent dummy text"}'
        #obj3.value = bytes.fromhex('48deadbeefdeadbeef') #dummy CBOR
        obj3.value = cbor.dumps(["Some","embedded","CBOR",[1,2,3]])

        grasp.flood(test_nonce, 0, grasp.tagged_objective(obj1,None),
                    grasp.tagged_objective(obj2,None),
                    grasp.tagged_objective(obj3,None))

###################################
# Test code: Listen Synchronize as from Boot ASA
###################################

        boot_obj.value = [1,"two",3]
        boot_obj.synch = True
        err = grasp.listen_synchronize(boot_nonce, boot_obj)
        grasp.tprint("Listen synch", grasp.etext[err])
        grasp.tprint(grasp._obj_registry[1].objective.name, "value", grasp._obj_registry[1].objective.value)

###################################
# Test code: call Synchronize as from EX1
###################################
        time.sleep(5)

        err, result = grasp.synchronize(test_nonce, obj2, None, 5000)
        if not err:
            grasp.tprint("Flooded synch obj2", result.value)
        else:
            grasp.tprint("Synch fail obj2", grasp.etext[err])

        err, result = grasp.synchronize(test_nonce, obj3, None, 5000)
        if not err:
            grasp.tprint("Flooded synch obj3", result.value)
        else:
            grasp.tprint("Synch fail obj3", grasp.etext[err])    

  
        #this should fail as test_obj was neither flooded or listened for.
        err, result = grasp.synchronize(test_nonce, test_obj, None, 5000)
        if not err:
            grasp.tprint("Synch test_obj (should fail)", result.value)
        else:
            grasp.tprint("Synch fail test_obj (should fail)", grasp.etext[err])

        boot2_obj = grasp.objective("Boot")
        boot2_obj.synch = True

        err, result = grasp.synchronize(test_nonce, boot2_obj, None, 5000)
        if not err:
            grasp.tprint("Synch boot2_obj", result.name, result.value)
        else:
            grasp.tprint("Synch fail boot2_obj", grasp.etext[err])


###################################
# Test code: print obj_registry
# and flood cache
###################################

        grasp.tprint("Objective registry contents:")         
        for x in grasp._obj_registry:
            o= x.objective
            grasp.tprint(o.name,"ASA:",x.asa_id,"Listen:",x.listening,"Neg:",o.neg,
                   "Synch:",o.synch,"Count:",o.loop_count,"Value:",o.value)
        grasp.tprint("Flood cache contents:")            
        for x in grasp._flood_cache:
            grasp.tprint(x.objective.name,"count:",x.objective.loop_count,"value:",
                         x.objective.value,"source:",x.source)
        time.sleep(5)

###################################
# Test code: check flood cache for Tag 24 case
###################################

        flobj = grasp.objective("Intent.PrefixManager")
        flobj.synch = True
        err, tobs = grasp.get_flood(test_nonce,flobj)
        if not err:
            for x in tobs:
                try:
                    grasp.tprint("Flooded CBOR",x.objective.name,cbor.loads(x.objective.value))
                except:
                    grasp.tprint("Flooded raw",x.objective.name,x.objective.value)

###################################
# Test code: deregister and then
# attempt synch            
###################################

        err = grasp.deregister_obj(boot_nonce, boot_obj)
        if not err:
            grasp.tprint("Deregistered Boot",)
        else:
            grasp.tprint("Deregister failure",grasp.etext[err])
            
        err, result = grasp.synchronize(test_nonce, boot2_obj, None, 5000)
        if not err:
            grasp.tprint("Synch boot2_obj (should fail)", result.name, result.value)
        else:
            grasp.tprint("Synch fail boot2_obj (should fail)", grasp.etext[err])

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

        grasp.deregister_asa(test_nonce,"ASA-1")
        grasp.tprint("Exiting ASA test thread")

###################################
# Test code: first negotiator
###################################

class Neg1(threading.Thread):
    """First test negotiator"""
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        global cheat_nonce
        reserves = grasp._prng.randint(100, 400)
        wt = grasp._prng.randint(15000, 40000)
        grasp.tprint("Reserves: $",reserves, "wait:",wt)
        err, asa_nonce=grasp.register_asa("Neg1") #assume it worked
        obj = grasp.objective("EX2")
        obj.neg = True
        #obj.loop_count = 2  #for testing purposes
        grasp.register_obj(asa_nonce, obj) #assume it worked
        cheat_nonce = asa_nonce #pass the nonce to the other negotiator!
        #attempt to listen
        err, snonce, answer = grasp.listen_negotiate(asa_nonce, obj)
        if err:
            grasp.tprint("listen_negotiate error:",grasp.etext[err])
        else:
            grasp.tprint("listened, answer",answer.name, answer.value)
            grasp.tprint("Source was", snonce.id_source)
            result=True
            reason=None
            concluded=False
            if answer.value[0]!="NZD":
                result=False
                reason="Invalid currency"
            elif answer.value[1] > reserves/2:
                answer.value = ["NZD",int(reserves/2)]
                err,temp,answer2 = grasp.negotiate_step(asa_nonce, snonce, answer, 1000)
                grasp.tprint("Step1 gave:", err, temp, answer2)
                if (not err) and (not temp):
                    concluded=True
                    grasp.tprint("Negotiation succeeded", answer2.value)                 
                elif not err:
                    err1 = grasp.negotiate_wait(asa_nonce, snonce, wt)
                    grasp.tprint("Tried wait:", grasp.etext[err1])
                    time.sleep(20) #note - if wt<20000 this tests anomaly handling
                    grasp.tprint("Woke up")
                    answer2.value = ["NZD",int(0.75*reserves)]
                    err2,temp,answer3 = grasp.negotiate_step(asa_nonce, snonce, answer2, 1000)
                    grasp.tprint("Step2 gave:", err2, temp, answer3)
                    if (not err2) and (not temp):
                        concluded=True
                        grasp.tprint("Negotiation succeeded", answer3.value)
                    elif not err2:
                        result=False
                        if reserves%2:
                            reason="Insufficient funds"
                        else:
                            reason=u"Недостаточно средств"
                    else:
                        #other end rejected
                        concluded=True
                        grasp.tprint("Peer reject2:",answer3)                    
                else:    
                    #other end rejected
                    concluded=True
                    grasp.tprint("Peer reject1:",answer2)
            else: #can accept the requested value
                pass
            if not concluded:
                err = grasp.end_negotiate(asa_nonce, snonce, result, reason=reason)
                if err:
                    grasp.tprint("end_negotiate error:",grasp.etext[err])
        grasp.tprint("Exit")

###################################
# Test code: second negotiator
###################################

class Neg2(threading.Thread):
    """Second test negotiator"""
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        global cheat_nonce
        
        
        iwant = grasp._prng.randint(10, 500)
        grasp.tprint("Asking for $",iwant)
        err, asa_nonce2=grasp.register_asa("Neg2") #assume it worked
        obj = grasp.objective("EX2")
        obj.neg = True
        #obj.loop_count = 2  #for testing purposes
        while cheat_nonce == None:
            time.sleep(1) #we should exit after neg1 has registered the objective
        asa_nonce = cheat_nonce #now we can pretend to own the objective
        grasp.tprint("Got nonce", asa_nonce)
        err, ll = grasp.discover(asa_nonce, obj, 5000)
        if ll==[]:
            grasp.tprint("Discovery failed: exit")
            return
        grasp.tprint("Discovered locator", ll[0].locator)
        #attempt to negotiate
        obj.value = ["NZD",iwant]
        if not iwant%7:
            obj.value = ["USD",iwant]  # for testing purposes
        err, snonce, answer = grasp.req_negotiate(asa_nonce, obj, ll[0], None)
        if err:
            if err==grasp.errors.declined and answer!="":
                _t = answer
            else:
                _t = grasp.etext[err]
            grasp.tprint("req_negotiate error:",_t)
        elif (not err) and snonce:
            grasp.tprint("requested, session_nonce:",snonce,"answer",answer)
            if answer.value[1]<0.75*iwant: 
                answer.value[1] = int(0.75*iwant)
                err,temp,answer2 = grasp.negotiate_step(asa_nonce, snonce, answer, 1000)
                grasp.tprint("Step1 gave:", err, temp, answer2)
                if (not err) and (not temp):
                    grasp.tprint("Negotiation succeeded", answer.value)
                elif not err:
                    #not acceptable, try one more time
                    answer2.value[1] = int(0.6*iwant)
                    #at random, throw an invalid format of message
                    if not iwant%3:
                        grasp.tprint("Trying badmess")
                        grasp._make_badmess = True
                    err,temp,answer3 = grasp.negotiate_step(asa_nonce, snonce, answer2, 1000)
                    grasp.tprint("Step2 gave:", err, temp, answer3)
                    if (not err) and (not temp):
                        grasp.tprint("Negotiation succeeded", answer3.value)
                    elif (not err):
                        #not acceptable
                        err = grasp.end_negotiate(asa_nonce, snonce, False, reason="You are mean!")
                        if err:
                            grasp.tprint("end_negotiate error:",grasp.etext[err])
                    else:
                        #other end rejected
                        grasp.tprint("Peer reject:",answer3)    
                else:    
                    #other end rejected
                    grasp.tprint("Peer reject:",answer2)                         
            else: #acceptable answer
                err = grasp.end_negotiate(asa_nonce, snonce, True)
                if not err:
                    grasp.tprint("Negotiation succeeded", answer.value)
                else:
                    grasp.tprint("end_negotiate error:",grasp.etext[err])
        else: #acceptable answer first time
            grasp.tprint("Negotiation succeeded", answer.value)
                
            
        grasp.tprint("Exit")

def ASAtest():
    """Convenience function for manual test runs"""
    testASA().start()

#### end of test ASA stuff #########  
