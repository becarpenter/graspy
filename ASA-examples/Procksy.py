#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""This is some demo code showing how a BRSKI proxy finds
a registrar in an ANIMA network using graspi. This version
also shows how the proxy advertises itself by flooding
to on-link nodes seeking a proxy (pledges), per RFC8995.
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
import ipaddress
import random
_prng = random.SystemRandom() # best PRNG we can get

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
        
###################################
# Function to flood an objective
###################################

def floodout(registrar):
    
    r_addr = registrar.locator
    r_port = registrar.port
    r_proto = registrar.protocol
    graspi.tprint("Chose registrar", r_addr, r_proto, r_port)
  
    ###################################
    # Finalise the locator
    ###################################
    

    proxy_locator.protocol = registrar.protocol
    if registrar.protocol == socket.IPPROTO_TCP:            
        proxy_locator.port = t_port
    elif registrar.protocol == socket.IPPROTO_UDP:        
        proxy_locator.port = u_port
    elif registrar.protocol == socket.IPPROTO_IPV6:
        proxy_locator.port = 0
    else:
        return # unknown method
    
    ###################################
    # Flood it out for the pledges
    ###################################
    
    graspi.tprint("Flooding",proxy_obj.name, proxy_locator.locator, proxy_locator.protocol, proxy_locator.port)
    graspi.flood(_asa_nonce, proxy_ttl, graspi.tagged_objective(proxy_obj, proxy_locator))
    return


###################################
# Main thread starts here
###################################

graspi.tprint("==========================")
graspi.tprint("ASA Procksy is starting up.")
graspi.tprint("==========================")

#graspi.test_mode = True # tell everybody it's a test, will print extra diagnostics
time.sleep(2) # time to read the text

graspi.skip_dialogue(selfing=True, be_dull=True)

####################################
# Register this ASA
####################################

# The ASA name is arbitrary - it just needs to be
# unique in the GRASP instance.

_err,_asa_nonce = graspi.register_asa("Procksy")
if not _err:
    graspi.tprint("ASA Procksy registered OK")
else:
    graspi.tprint("ASA registration failure:",graspi.etext[_err])
    exit()

####################################
# Construct a GRASP objective
####################################

# This is an empty GRASP objective to find the registrar
# It's only used for get_flood so doesn't need to be filled in

reg_obj = graspi.objective("AN_join_registrar")
reg_obj.synch = True

####################################
# Create ports for the proxy's communication
# with pledges
####################################

# For this demo, we just make up some numbers:

t_port = 11800 + _prng.randint(0,5) #slightly random for demo
u_port = 11900 + _prng.randint(0,5) #slightly random for demo

proxy_address = ipaddress.IPv6Address('::') # This is the unspecified address,
                                     # which signals link-local address to API
proxy_ttl = 180000 #milliseconds to live of the announcement

####################################
# Construct a correponding asa_locator
####################################

proxy_locator = graspi.asa_locator(proxy_address,0,False)
proxy_locator.is_ipaddress = True


####################################
# Construct the GRASP objective to announce the proxy
####################################

proxy_obj = graspi.objective("AN_proxy")
proxy_obj.synch = True
proxy_obj.value = ""
# proxy_obj.loop_count not set, the API forces it to 1 for link-local use


####################################
# Register the GRASP objective
####################################

_err = graspi.register_obj(_asa_nonce, proxy_obj)
if not _err:
    graspi.tprint("Objective", proxy_obj.name,"registered OK")
else:
    graspi.tprint("Objective registration failure:", graspi.etext[_err])
    exit() # demo code doesn't handle registration errors
    
####################################
# Start pretty printing
####################################

graspi.init_bubble_text("BRSKI Join Proxy")
graspi.tprint("Proxy starting now")

###################################
# Now find the registrar and pick one or two methods
###################################

while True:
    registrar1 = None
    registrar2 = None
    _err, _results = graspi.get_flood(_asa_nonce, reg_obj)
    if not _err:
        # _results contains the returned locators if any       
        for x in _results:                
            # use whatever logic you want to decide which results to use.
            # For the demo code, we just pick one or two at random:
            graspi.tprint("Got", reg_obj.name, "at",
                         x.source.locator, x.source.protocol, x.source.port)
            if (not registrar1) and _prng.randint(0,2):
                registrar1 = x.source
            elif _prng.randint(0,2):
                if x.source != registrar1:
                    registrar2 = x.source
  

    else:
        graspi.tprint("get_flood failed", graspi.etext[_err])

    ###################################
    # Flood the chosen ones to neighbors
    ###################################
    
    if registrar1:
        #graspi.tprint("Floodout1")
        floodout(registrar1)
        if registrar2:
            #graspi.tprint("Floodout2")
            floodout(registrar2)

        ###################################
        # Listen for a pledge with timeout
        ###################################

        # Here, do the socket calls etc. to listen
        # for a BRSKI request from a pledge.
        # But for the demo, we just pretend...
        time.sleep(5)
        # simulate no request from pledge
        if _prng.randint(0,2) == 0:
            graspi.tprint("No pledge contacted proxy")
        else:
            
            ###################################
            # BRSKI request received, now proxy it
            ###################################
            
            # Here, do the socket calls etc. to talk
            # to the registrar.
            # But for the demo, we just pretend...

            try:
                graspi.tprint("Pretending to contact registrar")
                # (socket calls etc)
                # simulate a random failure with a divide-by-zero
                _= 1/_prng.randint(0,3)
                
            except:
                # Socket failure, we should mark this registrar as expired.
                graspi.tprint("Communication failed, expiring that registrar")
                
            ###################################    
            # Wait and loop back to find another registrar
            # and wait for another pledge.
            ###################################
    else:
        graspi.tprint("No registrar found, waiting to try again")

    time.sleep(18) # wait chosen to avoid synchronicity with Reggie
