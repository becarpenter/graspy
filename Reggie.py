#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""This is some demo code showing how a BRSKI registrar would
provide its contact details to an ANIMA network using GRASP. The
actual BRSKI transactions are not included.
"""

import sys
sys.path.insert(0, '..') # in case grasp.py is one level up
import grasp
import threading
import time
import socket


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
grasp.tprint("ASA Reggie is starting up.")
grasp.tprint("==========================")
grasp.tprint("Reggie is a demonstration Autonomic Service Agent.")
grasp.tprint("It mimics a BRSKI Join Registrar by providing")
grasp.tprint("the methods it supports, with associated locators,")
grasp.tprint("as synchronized GRASP objectives.")
grasp.tprint("Then it pretends to wait for BRSKI traffic.")
grasp.tprint("This version corresponds to")
grasp.tprint("draft-carpenter-anima-ani-objectives-02")
grasp.tprint("On Windows or Linux, there should be a nice window")
grasp.tprint("that displays the process.")
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

_err,_asa_nonce = grasp.register_asa("Reggie")
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
# Construct a correponding GRASP locator option
####################################

tcp_locator = [grasp.O_IPv6_LOCATOR, tcp_address.packed, tcp_proto, tcp_port]

####################################
# Create a UDP port for BRSKI-UDP
####################################

# For this demo, we just make up some numbers:

udp_port = 880
udp_proto = socket.IPPROTO_UDP
udp_address = grasp._my_address # current address determined by GRASP kernel

####################################
# Construct a correponding GRASP locator option
####################################

udp_locator = [grasp.O_IPv6_LOCATOR, udp_address.packed, udp_proto, udp_port]

####################################
# Create a dummy IP-in-IP port for BRSKI-IPIP
####################################

# For this demo, we just make up some numbers:

ipip_port = None
ipip_proto = socket.IPPROTO_IPV6
ipip_address = grasp._my_address # current address determined by GRASP kernel

####################################
# Construct a correponding GRASP locator option
####################################

ipip_locator = [grasp.O_IPv6_LOCATOR, ipip_address.packed, ipip_proto, ipip_port]

####################################
# Construct the GRASP objective
####################################

radius = 6    # Limit the radius of discovery

reg_obj = grasp.objective("AN_join_registrar")
reg_obj.loop_count = radius
reg_obj.synch = True    # Because it's synched, not negotiated
reg_obj.value = [["BRSKI-TCP", tcp_locator],
                 ["BRSKI-UDP", udp_locator],
                 ["BRSKI-IPIP", ipip_locator]]

####################################
# Register the GRASP objective
####################################

_err = grasp.register_obj(_asa_nonce,reg_obj)
if not _err:
    grasp.tprint("Objective", reg_obj.name, "registered OK")
else:
    grasp.tprint("Objective registration failure:", grasp.etext[_err])
    exit() # demo code doesn't handle registration errors

# If we wanted to allow multiple simultaneous ASAs to register
# this objective, we would include an optional parameter thus:
#
# _ok, _temp = grasp.register_obj(_asa_nonce,reg_obj,overlap=True)

####################################
# Start pretty printing
####################################

grasp.init_bubble_text("BRSKI Join Registrar")

        
###################################
# Listen for synchronization requests
# (which makes the objective discoverable)
###################################
grasp.tprint("Listening for synch:",reg_obj.name)

# This is a non-blocking call
_err = grasp.listen_synchronize(_asa_nonce, reg_obj)
if _err:
    grasp.tprint("Listen_synch failed:", grasp.etext[_err])
else:

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

    