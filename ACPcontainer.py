#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""This is some demo code showing how an established ACP node
would advertise itself by flooding to on-link nodes seeking
to join the ACP. Also how it could advertise itself as an
EST server.
"""

import sys
sys.path.insert(0, '..') # in case grasp.py is one level up
import grasp
import threading
import time
import socket
try:
    socket.IPPROTO_IPV6
except:
    socket.IPPROTO_IPV6 = 41
import ipaddress

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

grasp.tprint("================================")
grasp.tprint("ASA ACPcontainer is starting up.")
grasp.tprint("================================")
grasp.tprint("This is a demonstration Autonomic Service Agent.")
grasp.tprint("It mimics an established ACP node by")
grasp.tprint("announcing itself to potential on-link")
grasp.tprint("peers by a flooded GRASP objective.")
grasp.tprint("It also announce itself as an EST server.")
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

_err,_asa_nonce = grasp.register_asa("ACPcontainer")
if not _err:
    grasp.tprint("ASA ACPcontainer registered OK")
else:
    grasp.tprint("ASA registration failure:",grasp.etext[_err])
    exit()

####################################
# Construct GRASP objectives
####################################

acp_obj = grasp.objective("AN_ACP")
acp_obj.synch = True
acp_obj.discoverable = False  #override default
acp_obj.value = "IKEv2"
# acp_obj.loop_count not set, the API forces it to 1 for link-local use

est_obj = grasp.objective("SRV.est")
est_obj.synch = True
est_obj.discoverable = False  #override default
est_obj.value = "EST-TLS" #for RFC7030
# est_obj.loop_count not set, the API forces it to 1 for link-local use

####################################
# Create an asa_locator for IKEv2
# communication with peers
####################################

acp_address = grasp._unspec_address # This is the unspecified address,
                                   # which signals link-local address to API
acp_ttl = 120000 #milliseconds to live of the announcement
acp_locator = grasp.asa_locator(acp_address,0,False)
acp_locator.is_ipaddress = True
acp_locator.protocol = socket.IPPROTO_UDP

####################################
# Create an asa_locator for EST-TLS 
# communication with peers
####################################

est_address = grasp._unspec_address # This is the unspecified address,
                                   # which signals link-local address to API
est_ttl = 120000 #milliseconds to live of the announcement
est_locator = grasp.asa_locator(est_address,0,False)
est_locator.is_ipaddress = True
est_locator.protocol = socket.IPPROTO_TCP

####################################
# Register the objectives
####################################

_err = grasp.register_obj(_asa_nonce, acp_obj)
if not _err:
    grasp.tprint("Objective", acp_obj.name,"registered OK")
else:
    grasp.tprint("Objective registration failure:", grasp.etext[_err])
    exit() # demo code doesn't handle registration errors

_err = grasp.register_obj(_asa_nonce, est_obj)
if not _err:
    grasp.tprint("Objective", est_obj.name,"registered OK")
else:
    grasp.tprint("Objective registration failure:", grasp.etext[_err])
    exit() # demo code doesn't handle registration errors
    
####################################
# Start pretty printing
####################################

grasp.init_bubble_text("ACP container")
grasp.tprint("ACPcontainer starting now")

###################################
# Now flood the objectives out at
# a suitable frequency
###################################

while True:
    acp_locator.port = 500 + grasp._prng.randint(0,5) #slightly random for demo
    est_locator.port = 80 + grasp._prng.randint(0,5)
    grasp.tprint("Flooding",acp_obj.name, acp_locator.protocol, acp_locator.port,
                 "and",est_obj.name, est_locator.protocol, est_locator.port)
    grasp.flood(_asa_nonce, acp_ttl, grasp.tagged_objective(acp_obj, acp_locator),
                grasp.tagged_objective(est_obj, est_locator))
##    grasp.flood(_asa_nonce, est_ttl, grasp.tagged_objective(est_obj, est_locator))

    time.sleep(60) #The default SHOULD be 60 seconds, the
                   #value SHOULD be operator configurable.
                   #(configure here with your preferred editor)
