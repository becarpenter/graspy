#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""########################################################
########################################################
# pusher is a demonstration Autonomic Service Agent.
# It supports the unregistered GRASP objective 411:mvFile
# in order to push files to a client ASA.
#
# See grasp.py for license, copyright, and disclaimer.
#
########################################################"""

import grasp
import threading
import time
import cbor

###################################
# Support function for CBOR coded
# objective value
###################################

def detag(val):
    """ Decode CBOR if necessary
        -> decoded_object, was_CBOR"""
    try:
        return cbor.loads(val), True
    except:
        try:
            if val.tag == 24:
                return cbor.loads(val.value), True
        except:
            return val, False

####################################
# Support function for negotiator
####################################

def endit(snonce, r):
    """Send end_negotiate with reason string"""
    grasp.tprint("Failed", r)
    err = grasp.end_negotiate(asa_nonce, snonce, False, reason=r)
    if err:
        grasp.tprint("end_negotiate error:",grasp.etext[err])      

####################################
# Thread to handle a negotiation
####################################

class negotiator(threading.Thread):
    """Thread to negotiate objective as master"""
    def __init__(self, snonce, nobj):
        threading.Thread.__init__(self)
        self.snonce = snonce
        self.nobj = nobj

    def run(self):
        requested_obj=self.nobj
        snonce=self.snonce
        
        requested_obj.value, _cbor = detag(requested_obj.value)
        if _cbor:
            grasp.tprint("CBOR value decoded")

        grasp.tprint("Got request for", requested_obj.value)
        if requested_obj.dry:
            endit(snonce,"Dry run not supported")
        else:            
            try:
                file = open(requested_obj.value, "rb")
            except Exception as e:
                grasp.tprint("File open error")
                endit(snonce,str(e))
                return
            chunk = True
            grasp.tprint("Starting transfer")
            while chunk:

                chunk=file.read(1024)
                grasp.ttprint("Sending",len(chunk),"bytes")
                requested_obj.value = chunk
                #bump the loop count for next chunk
                requested_obj.loop_count += 1
                
                if _cbor:
                    requested_obj.value=cbor.dumps(requested_obj.value)
                    
                #send chunk as negotiation step                    
                err,temp,requested_obj = grasp.negotiate_step(asa_nonce, snonce, requested_obj, 1000)
                grasp.ttprint("Negotiation step gave:", err, temp, requested_obj)

                if (not err) and temp==None:
                    # the other end signalled End/Accept
                    grasp.tprint("Ended transfer")
                    
                elif not err:
                    requested_obj.value, _ = detag(requested_obj.value)
                    if _:
                        grasp.ttprint("CBOR value decoded")
                        
                    if (not len(chunk)) or (requested_obj.value != 'ACK'):
                        # we got a reply after EOF, or a bad ACK
                        grasp.tprint("Unexpected reply: loop count", requested_obj.loop_count,
                                     "value",requested_obj.value)
                        endit(snonce, "Unexpected reply")
                        break
                else:    
                    #other end rejected or loop count exhausted
                    if err==grasp.errors.loopExhausted:
                        # we need to signal the end
                        endit(snonce, grasp.etext[err])
                    else:
                        grasp.tprint("Failed:",grasp.etext[err])
                    break
            file.close()
                        

        #end of negotiation

grasp.tprint("==========================")
grasp.tprint("pusher is starting up.")
grasp.tprint("==========================")
grasp.tprint("pusher is a demonstration Autonomic Service Agent.")
grasp.tprint("It runs indefinitely as file transfer agent.")
grasp.tprint("It is implemented using a negotiation objective")
grasp.tprint("that can handle overlapping requests.")
grasp.tprint("On Windows or Linux, there should be a nice")
grasp.tprint("window that displays the process.")
grasp.tprint("==========================")

####################################
# General initialisation
####################################

time.sleep(8) # so the user can read the text
grasp.skip_dialogue(selfing=True)

####################################
# Register ASA/objective
####################################

err,asa_nonce = grasp.register_asa("pusher")
if not err:
    grasp.tprint("ASA pusher registered OK")

else:
    exit()
    
supported_obj = grasp.objective("411:mvFile")
supported_obj.loop_count = 4
supported_obj.neg = True


err = grasp.register_obj(asa_nonce,supported_obj)
if not err:
    grasp.tprint("Objective", supported_obj.name, "registered OK")
else:
    exit()

###################################
# Set up pretty printing
###################################

grasp.init_bubble_text("pusher")
grasp.tprint("pusher is listening")

###################################
# Negotiate as listener for ever
###################################

while True:
    # listen for negotiation request
    err, snonce, request = grasp.listen_negotiate(asa_nonce, supported_obj)
    if err:
        grasp.tprint("listen_negotiate error:",grasp.etext[err])
        time.sleep(5) #to calm things if there's a looping error
    else:
        #got a new negotiation request; kick off a separate negotiator
        #so that multiple requests can be handled in parallel
        negotiator(snonce, request).start()



