#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""This is some demo code showing how a BRSKI registrar provides
its contact details to an ANIMA network using GRASP flooding
per RFC8995.
The actual BRSKI transactions are not included. 
"""

import sys
sys.path.insert(0, '..') # in case graspi.py is one level up
import graspi
import threading
import time
import socket
#fix very old bug
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
    graspi.tprint("Objective registry contents:")         
    for x in graspi.grasp._obj_registry:
        o= x.objective
        graspi.tprint(o.name,"ASA:",x.asa_id,"Listen:",x.listening,"Neg:",o.neg,
               "Synch:",o.synch,"Count:",o.loop_count,"Value:",o.value)
    graspi.tprint("Flood cache contents:")            
    for x in graspi.grasp._flood_cache:
        graspi.tprint(x.objective.name,"count:",x.objective.loop_count,"value:",
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
            graspi.flood(asa_nonce, 120000,
                        graspi.tagged_objective(reg_obj,tcp_locator))
            
    #not using          graspi.tagged_objective(reg_obj,udp_locator),
    #not using          graspi.tagged_objective(reg_obj,ipip_locator))

###################################
# Main thread starts here
###################################

graspi.tprint("==========================")
graspi.tprint("ASA Reggie is starting up.")
graspi.tprint("==========================")

#graspi.test_mode = True # set if you want detailed diagnostics
time.sleep(2) # time to read the text

graspi.skip_dialogue(selfing=True, be_dull=True)

####################################
# Register this ASA
####################################

# The ASA name is arbitrary - it just needs to be
# unique in the GRASP instance. If you wanted to
# run two registrars in one GRASP instance, they
# would need different names. For example the name
# could include a timestamp.

_err, asa_nonce = graspi.register_asa("Reggie")
if not _err:
    graspi.tprint("ASA Reggie registered OK")
else:
    graspi.tprint("ASA registration failure:",graspi.etext[_err])
    exit() # demo code doesn't handle registration errors

####################################
# Create a TCP port for BRSKI-TCP
####################################

# For this demo, we just make up some numbers:

tcp_port = 80
tcp_proto = socket.IPPROTO_TCP
tcp_address = graspi.grasp._my_address # current address determined by GRASP kernel

####################################
# Construct a correponding GRASP ASA locator
####################################

tcp_locator = graspi.asa_locator(tcp_address, None, False)
tcp_locator.protocol = tcp_proto
tcp_locator.port = tcp_port
tcp_locator.is_ipaddress = True

####################################
# Create a UDP port for BRSKI-UDP
####################################

# For this demo, we just make up some numbers:

udp_port = 880
udp_proto = socket.IPPROTO_UDP
udp_address = graspi.grasp._my_address # current address determined by GRASP kernel

####################################
# Construct a correponding GRASP ASA locator
####################################

udp_locator = graspi.asa_locator(udp_address, None, False)
udp_locator.protocol = udp_proto
udp_locator.port = udp_port
udp_locator.is_ipaddress = True

####################################
# Create a dummy IP-in-IP port for BRSKI-IPIP
####################################


ipip_port = 0
ipip_proto = socket.IPPROTO_IPV6
ipip_address = graspi.grasp._my_address # current address determined by GRASP kernel

####################################
# Construct a correponding GRASP ASA locator
####################################

ipip_locator = graspi.asa_locator(ipip_address, None, False)
ipip_locator.protocol = ipip_proto
ipip_locator.port = ipip_port
ipip_locator.is_ipaddress = True

####################################
# Construct the GRASP objective
####################################

radius = 255    # Limit the radius of flooding

reg_obj = graspi.objective("AN_join_registrar")
reg_obj.loop_count = radius
reg_obj.synch = True    # needed for flooding
reg_obj.value = None

####################################
# Register the GRASP objective
####################################

_err = graspi.register_obj(asa_nonce,reg_obj)
if not _err:
    graspi.tprint("Objective", reg_obj.name, "registered OK")
else:
    graspi.tprint("Objective registration failure:", graspi.etext[_err])
    exit() # demo code doesn't handle registration errors


####################################
# Start pretty printing
####################################

graspi.init_bubble_text("BRSKI Join Registrar (flooding method)")
graspi.tprint("Registrar starting now")

####################################
# Start flooding thread
####################################


flooder().start()
graspi.tprint("Flooding", reg_obj.name, "for ever")
        
###################################
# Listen for requests
###################################

# Here, launch a thread to do the real work of the registrar
# via the various ports But for the demo, we just pretend...
graspi.tprint("Pretending to listen to ports", tcp_port,",", udp_port,
             "and for IP-in-IP")
    

###################################
# Do whatever needs to be done in the main thread
###################################

# At a minimum, the main thread should keep an eye
# on the other threads and restart them if needed.
# For the demo, we just dump some diagnostic data...

while True:
    time.sleep(30)
    graspi.tprint("Registrar main loop diagnostic dump:")
    dump_some()

    
