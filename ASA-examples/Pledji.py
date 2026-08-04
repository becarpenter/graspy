#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""This is some demo code showing how a BRSKI pledge finds
find a proxy in an ANIMA network using GRASP per RFC8995.
The actual BRSKI transactions are not included.
"""

import sys
sys.path.insert(0, '..') # assumes graspi.py is one level up
import graspi
import threading
import time
import socket
#fix very old bug
try:
    socket.IPPROTO_IPV6
except:
    socket.IPPROTO_IPV6 = 41
import random
_prng = random.SystemRandom() # best PRNG we can get

###################################
# Map protocols to method names
###################################
pm={socket.IPPROTO_UDP: "UDP",
    socket.IPPROTO_TCP: "TCP",
    socket.IPPROTO_IPV6: "IPIP"}

###################################
# Utility routine for debugging:
# Print out the GRASP objective registry
# and flood cache
###################################

def dump_some():
    graspi.tprint("Objective registry contents:")         
    for x in graspi._obj_registry:
        o= x.objective
        graspi.tprint(o.name,"ASA:",x.asa_id,"Listen:",x.listening,"Neg:",o.neg,
               "Synch:",o.synch,"Count:",o.loop_count,"Value:",o.value)
    graspi.tprint("Flood cache contents:")            
    for x in graspi._flood_cache:
        graspi.tprint(x.objective.name,"count:",x.objective.loop_count,"value:",
                     x.objective.value,"source",x.source.locator, x.source.protocol,
                     x.source.port,"expiry",x.source.expire)

###################################
# Main thread starts here
###################################


graspi.tprint("==========================")
graspi.tprint("ASA Pledji is starting up.")
graspi.tprint("==========================")


#graspi.test_mode = True # tell everybody it's a test, will print extra diagnostics
time.sleep(2) # time to read the text

graspi.skip_dialogue(selfing=True, be_dull=True)


####################################
# Register this ASA
####################################

# The ASA name is arbitrary - it just needs to be
# unique in the GRASP instance.

_err,_asa_nonce = graspi.register_asa("Pledji")
if not _err:
    graspi.tprint("ASA Pledji registered OK")
else:
    graspi.tprint("ASA registration failure:",graspi.etext[_err])
    exit()

####################################
# Construct a GRASP objective
####################################

# This is an empty GRASP objective to find the proxy
# It's only used for get_flood so doesn't need to be filled in

proxy_obj = graspi.objective("AN_proxy")
proxy_obj.synch = True


graspi.init_bubble_text("BRSKI Pledge (flooding method)")
graspi.tprint("Pledge starting now")

###################################
# Now find the proxy(s)
###################################

while True:
    proxy = None
    _err, _results = graspi.get_flood(_asa_nonce, proxy_obj)
    if not _err:
        # _results contains all the unexpired tagged objectives
        graspi.tprint("Found",len(_results),"result(s)")
        for x in _results:
            # Extract the details
            try:
                x.method = pm[x.source.protocol]
            except:
                x.method = "Unknown"            
            # Print the result
            graspi.tprint(x.objective.name, "flooded from", x.source.locator, x.source.protocol,
                        x.source.port,"expiry",x.source.expire,
                        "method", x.method)
            
            # use whatever logic you want to decide which proxy to use.
            # For the demo code, we randomize somewhat:
            if _prng.randint(0,1):
                proxy = x

    else:
        graspi.tprint("get_flood failed", graspi.etext[_err])

    if proxy:
        p_addr = proxy.source.locator
        p_proto = proxy.source.protocol
        p_port = proxy.source.port
        p_method = proxy.method
        graspi.tprint("Chose proxy: address", p_addr, "protocol", p_proto,
                     "port", p_port, "method", p_method)
        
        ###################################
        # Connect to the proxy
        ###################################

        # Here, do the socket calls etc. to talk
        # to the proxy.
        # But for the demo, we just pretend...
        
        try:
            graspi.tprint("Pretending to contact proxy")
            # (socket calls etc)
            # simulate a random failure with a divide-by-zero
            _= 1/graspi._prng.randint(0,3)
            
        except:
            # Socket failure, tag this proxy as expired.
            # (Since floods expire, eventually the bad proxy
            # will vanish anyway, but this call avoids the wait.)
            graspi.tprint("Communication failed, expiring that proxy")
            graspi.expire_flood(_asa_nonce, proxy)
            
        ###################################    
        # Wait and loop back to find another proxy
        ################################### 

    time.sleep(20) # wait chosen to avoid synchronicity with Procksy
