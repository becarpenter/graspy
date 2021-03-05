#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""This is some demo code showing how a new ACP peer would
find ACP neighbors. 
"""

import sys
sys.path.insert(0, '..') # assumes grasp.py is one level up
import grasp
import threading
import time
import socket
try:
    socket.IPPROTO_IPV6
except:
    socket.IPPROTO_IPV6 = 41


###################################
# Utility routine for debugging:
# Print out the GRASP objective registry
# and flood cache
###################################

def dump_some():
    grasp.tprint("Objective registry contents:")         
    for x in grasp._obj_registry:
        o= x.objective
        grasp.tprint(o.name,"ASA:",x.asa_id,"Listen:",x.listening,"Neg:",o.neg,
               "Synch:",o.synch,"Count:",o.loop_count,"Value:",o.value)
    grasp.tprint("Flood cache contents:")            
    for x in grasp._flood_cache:
        grasp.tprint(x.objective.name,"count:",x.objective.loop_count,"value:",
                     x.objective.value,"source",x.source.locator, x.source.protocol,
                     x.source.port,"expiry",x.source.expire)

###################################
# Main thread starts here
###################################


grasp.tprint("==========================")
grasp.tprint("ASA Newby is starting up.")
grasp.tprint("==========================")
grasp.tprint("Newby is a demonstration Autonomic Service Agent.")
grasp.tprint("It shows how a new ACP peer will find its")
grasp.tprint("ACP neighbors and EST servers.")
grasp.tprint("On Windows or Linux, there should soon be")
grasp.tprint("a nice window that displays the process.")
grasp.tprint("==========================")

#grasp.test_mode = True # tell everybody it's a test, will print extra diagnostics
time.sleep(8) # time to read the text


####################################
# Register this ASA
####################################

# The ASA name is arbitrary - it just needs to be
# unique in the GRASP instance.

_err,_asa_nonce = grasp.register_asa("Newby")
if not _err:
    grasp.tprint("ASA Newby registered OK")
else:
    grasp.tprint("ASA registration failure:",grasp.etext[_err])
    exit()

####################################
# Construct GRASP objectives
####################################

# These are empty GRASP objectives to find the peer(s)
# They are only used for get_flood so don't need to be filled in

acp_obj = grasp.objective("AN_ACP")
acp_obj.synch = True
est_obj = grasp.objective("SRV.est")
est_obj.synch = True


grasp.init_bubble_text("ACP Newby")
grasp.tprint("Newby starting now")

###################################
# Now find the flood(s)
###################################

while True:
    _err, _results = grasp.get_flood(_asa_nonce, acp_obj)
    if not _err:
        # _results contains all the unexpired tagged objectives
        grasp.tprint("Found",len(_results),"result(s) for",acp_obj.name)
        for x in _results:           
            # Print the result
            grasp.tprint(x.objective.name, "value", x.objective.value,
                         "locator", x.source.locator,
                         "interface", x.source.ifi,
                         "protocol", x.source.protocol,
                         "port", x.source.port,"expiry",x.source.expire)
    else:
        grasp.tprint("get_flood failed", grasp.etext[_err])

    _err, _results = grasp.get_flood(_asa_nonce, est_obj)
    if not _err:
        # _results contains all the unexpired tagged objectives
        grasp.tprint("Found",len(_results),"result(s) for",est_obj.name)
        for x in _results:           
            # Print the result
            grasp.tprint(x.objective.name, "value", x.objective.value,
                         "locator", x.source.locator,
                         "interface", x.source.ifi,
                         "protocol", x.source.protocol,
                         "port", x.source.port,"expiry",x.source.expire)
    else:
        grasp.tprint("get_flood failed", grasp.etext[_err])

            
    ###################################    
    # Wait and loop back to try again
    ################################### 

    time.sleep(20) # wait chosen to avoid synchronicity with ACPcontainer
