#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""This is an ASA whose purpose is to demonstrate objective
subscription in a GRASP/ACP environment.
"""

# Released under the BSD "Revised" License.
#                                                     
# Copyright (C) 2026 Brian E. Carpenter.                  
# All rights reserved.

# 20261012 First version

import sys
import threading
import time
import socket
import json
#sys.path.insert(0, '..') # in case graspi.py is one level up
import graspi


#########################################
#
# With a bit more work, the following two
# functions could be embedded in grasp.py,
# with `port` stored as a function of
# the asa handle.
#
########################################

port = None

def subscribe_topic(asa_handle, topic, timeout):
    """Subscribe to a topic - timeout in ms """
    
    global port

    ####################################
    # Make own UDP listener port
    ####################################
    if not port:
        err, port = graspi.grasp.listen_port(asa_handle)
        if not err:
            graspi.tprint(ASA_name, "has listen port", port)
        else:
            graspi.tprint("Listen port failure:",graspi.etext[err])
            return(err)
    
    ####################################
    # Construct a GRASP negotiation objective
    # and register it
    ####################################

    sub_obj = graspi.objective("SubscribeTopic")
    sub_obj.neg = True
    sub_obj.value = [True, topic, port, timeout] 

    err = graspi.register_obj(asa_handle, sub_obj)
    if not err or err == graspi.grasp.errors.objReg:
        graspi.tprint("Objective", sub_obj.name, "registered OK")
    else:
        graspi.tprint("Cannot register objective:", graspi.etext[err])
        return(err)
    
    ####################################
    # Request subscription
    ####################################

    err, shandle, rep_obj, reason = graspi.request_negotiate(asa_handle, sub_obj, None, None)

    if err:
        graspi.tprint("Error", graspi.etext[err], reason)
        return(err)
    else:
        graspi.tprint("Subscribed to", sub_obj.value[1])
        return(graspi.grasp.errors.ok)

def unsubscribe_topic(asa_handle, topic):
    """Unsubscribe from a topic"""
    global port
    if not port:
        return(graspi.grasp.errors.unspec)
    sub_obj = graspi.objective("SubscribeTopic")
    sub_obj.neg = True
    sub_obj.value = [False, topic, port, 0]
    err, shandle, rep_obj, reason = graspi.request_negotiate(asa_handle, sub_obj, None, None)
    if err:
        graspi.tprint("Error", graspi.etext[err], reason)
        return(err)
    else:
        graspi.tprint("Unsubscribed from", sub_obj.value[1])
        return(graspi.grasp.errors.ok)



###################################
# Main thread starts here
###################################

ASA_name = "subscribe" # Arbitrary ASA name, unique in the GRASP instance.

if not "idlelib" in sys.modules:
    sys.stdout.write("\x1b]2;"+ASA_name+"\x07") #Label window
    sys.stdout.flush()

# Note: silent=True would suppress all GRASP printing
graspi.skip_dialogue(selfing=True, figging=False) #, silent=True)

graspi.tprint(ASA_name, "is starting up.")

####################################
# Register this ASA
####################################

err, asa_handle = graspi.register_asa(ASA_name)
if not err:
    graspi.tprint(ASA_name, "registered OK")
else:
    graspi.tprint("ASA registration failure:",graspi.etext[err])
    sys.exit()

time.sleep(10) # wait until GRASP kernel is sure to be ready


####################################
# Request subscription
####################################
topic = "example.org:Sub/Intent/VoIPQoS"

err = subscribe_topic(asa_handle, topic, 0)

time.sleep(10)

err = subscribe_topic(asa_handle, topic+"/more", 0)

time.sleep(10)

####################################
# Cancel subscription
####################################

err = unsubscribe_topic(asa_handle, topic+"/more")

####################################
# Get flood
####################################

graspi.tprint("Will now wait for flooded value")

flob = graspi.objective(topic)
flob.synch = True

while True:  
    err, result = graspi.get_flood(asa_handle, flob)
    if err:
        graspi.tprint("Error", graspi.etext[err])
    else:
        if result:
            graspi.tprint(result[0].objective.value, result[0].source)
            #graspi.grasp.dump_all()
        else:
            graspi.tprint("No value")
    time.sleep(25)  # arbitrary wait
