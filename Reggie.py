#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""This is some demo code showing how a BRSKI registrar would
provide its contact details to an ANIMA network using GRASP. The
actual BRSKI transactions are not included. Flooding
version, per draft-ietf-anima-bootstrapping-keyinfra-09.
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

####################################
# Thread to flood the objective repeatedly
####################################

class flooder(threading.Thread):
    """Thread to flood objectve repeatedly"""
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        while True:
            time.sleep(60)
            reg_obj.value = "EST-TLS"
            grasp.flood(asa_nonce, 120000,
                        grasp.tagged_objective(reg_obj,tcp_locator))
            
    #not using          grasp.tagged_objective(reg_obj,udp_locator),
    #not using          grasp.tagged_objective(reg_obj,ipip_locator))

###################################
# Main thread starts here
###################################

grasp.tprint("==========================")
grasp.tprint("ASA Reggie is starting up.")
grasp.tprint("==========================")
grasp.tprint("Reggie is a demonstration Autonomic Service Agent.")
grasp.tprint("It mimics a BRSKI Join Registrar by providing")
grasp.tprint("the methods it supports, with associated locators,")
grasp.tprint("as synchronized GRASP objectives.")
grasp.tprint("Then it pretends to wait for BRSKI traffic.")
grasp.tprint("This version supports flooding,")
grasp.tprint("per draft-ietf-anima-bootstrapping-keyinfra-12")
grasp.tprint("On Windows or Linux, there should soon be")
grasp.tprint("a nice window that displays the process.")
grasp.tprint("==========================")



#grasp.test_mode = True # set if you want detailed diagnostics
time.sleep(8) # time to read the text



####################################
# Register this ASA
####################################

# The ASA name is arbitrary - it just needs to be
# unique in the GRASP instance. If you wanted to
# run two registrars in one GRASP instance, they
# would need different names. For example the name
# could include a timestamp.

_err, asa_nonce = grasp.register_asa("Reggie")
if not _err:
    grasp.tprint("ASA Reggie registered OK")
else:
    grasp.tprint("ASA registration failure:",grasp.etext[_err])
    exit() # demo code doesn't handle registration errors

####################################
# Create a TCP port for BRSKI-TCP
####################################

# For this demo, we just make up some numbers:

tcp_port = 80
tcp_proto = socket.IPPROTO_TCP
tcp_address = grasp._my_address # current address determined by GRASP kernel

####################################
# Construct a correponding GRASP ASA locator
####################################

tcp_locator = grasp.asa_locator(tcp_address, None, False)
tcp_locator.protocol = tcp_proto
tcp_locator.port = tcp_port
tcp_locator.is_ipaddress = True

####################################
# Create a UDP port for BRSKI-UDP
####################################

# For this demo, we just make up some numbers:

udp_port = 880
udp_proto = socket.IPPROTO_UDP
udp_address = grasp._my_address # current address determined by GRASP kernel

####################################
# Construct a correponding GRASP ASA locator
####################################

udp_locator = grasp.asa_locator(udp_address, None, False)
udp_locator.protocol = udp_proto
udp_locator.port = udp_port
udp_locator.is_ipaddress = True

####################################
# Create a dummy IP-in-IP port for BRSKI-IPIP
####################################


ipip_port = 0
ipip_proto = socket.IPPROTO_IPV6
ipip_address = grasp._my_address # current address determined by GRASP kernel

####################################
# Construct a correponding GRASP ASA locator
####################################

ipip_locator = grasp.asa_locator(ipip_address, None, False)
ipip_locator.protocol = ipip_proto
ipip_locator.port = ipip_port
ipip_locator.is_ipaddress = True

####################################
# Construct the GRASP objective
####################################

radius = 255    # Limit the radius of flooding

reg_obj = grasp.objective("AN_join_registrar")
reg_obj.loop_count = radius
reg_obj.synch = True    # needed for flooding
reg_obj.value = None

####################################
# Register the GRASP objective
####################################

_err = grasp.register_obj(asa_nonce,reg_obj)
if not _err:
    grasp.tprint("Objective", reg_obj.name, "registered OK")
else:
    grasp.tprint("Objective registration failure:", grasp.etext[_err])
    exit() # demo code doesn't handle registration errors


####################################
# Start pretty printing
####################################

grasp.init_bubble_text("BRSKI Join Registrar (flooding method)")
grasp.tprint("Registrar starting now")

####################################
# Start flooding thread
####################################


flooder().start()
grasp.tprint("Flooding", reg_obj.name, "for ever")
        
###################################
# Listen for requests
###################################

# Here, launch a thread to do the real work of the registrar
# via the various ports But for the demo, we just pretend...
grasp.tprint("Pretending to listen to ports", tcp_port,",", udp_port,
             "and for IP-in-IP")
    

###################################
# Do whatever needs to be done in the main thread
###################################

# At a minimum, the main thread should keep an eye
# on the other threads and restart them if needed.
# For the demo, we just dump some diagnostic data...

while True:
    time.sleep(30)
    grasp.tprint("Registrar main loop diagnostic dump:")
    dump_some()

    
