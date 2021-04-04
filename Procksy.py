#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""This is some demo code showing how a BRSKI proxy would
find a registrar in an ANIMA network using GRASP. This version
also shows how the proxy could advertise itself by flooding
to on-link nodes seeking a proxy. The actual BRSKI transactions
are not included.
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
# Function to flood an objective
###################################

def floodout(registrar):
    
    r_addr = registrar.locator
    r_port = registrar.port
    r_proto = registrar.protocol
    grasp.tprint("Chose registrar", r_addr, r_proto, r_port)
  
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
    
    grasp.tprint("Flooding",proxy_obj.name, proxy_locator.locator, proxy_locator.protocol, proxy_locator.port)
    grasp.flood(_asa_nonce, proxy_ttl, grasp.tagged_objective(proxy_obj, proxy_locator))
    return


###################################
# Main thread starts here
###################################

grasp.tprint("==========================")
grasp.tprint("ASA Procksy is starting up.")
grasp.tprint("==========================")
grasp.tprint("Procksy is a demonstration Autonomic Service Agent.")
grasp.tprint("It mimics a BRSKI Join Assistant (proxy) by")
grasp.tprint("looking for a registrar and then by announcing")
grasp.tprint("the methods it supports, with associated locators,")
grasp.tprint("as flooded GRASP objectives.")
grasp.tprint("Then it pretends to generate BRSKI traffic.")
grasp.tprint("This version uses floods to find a registrar,")
grasp.tprint("per draft-ietf-anima-bootstrapping-keyinfra-12")
#grasp.tprint('modulo an error in the "AN_proxy" definition')
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

_err,_asa_nonce = grasp.register_asa("Procksy")
if not _err:
    grasp.tprint("ASA Procksy registered OK")
else:
    grasp.tprint("ASA registration failure:",grasp.etext[_err])
    exit()

####################################
# Construct a GRASP objective
####################################

# This is an empty GRASP objective to find the registrar
# It's only used for get_flood so doesn't need to be filled in

reg_obj = grasp.objective("AN_join_registrar")
reg_obj.synch = True

####################################
# Create ports for the proxy's communication
# with pledges
####################################

# For this demo, we just make up some numbers:

t_port = 11800 + grasp._prng.randint(0,5) #slightly random for demo
u_port = 11900 + grasp._prng.randint(0,5) #slightly random for demo

proxy_address = grasp._unspec_address # This is the unspecified address,
                                     # which signals link-local address to API
proxy_ttl = 180000 #milliseconds to live of the announcement

####################################
# Construct a correponding asa_locator
####################################

proxy_locator = grasp.asa_locator(proxy_address,0,False)
proxy_locator.is_ipaddress = True


####################################
# Construct the GRASP objective to announce the proxy
####################################

proxy_obj = grasp.objective("AN_proxy")
proxy_obj.synch = True
proxy_obj.value = ""
# proxy_obj.loop_count not set, the API forces it to 1 for link-local use


####################################
# Register the GRASP objective
####################################

_err = grasp.register_obj(_asa_nonce, proxy_obj)
if not _err:
    grasp.tprint("Objective", proxy_obj.name,"registered OK")
else:
    grasp.tprint("Objective registration failure:", grasp.etext[_err])
    exit() # demo code doesn't handle registration errors
    
####################################
# Start pretty printing
####################################

grasp.init_bubble_text("BRSKI Join Proxy")
grasp.tprint("Proxy starting now")

###################################
# Now find the registrar and pick one or two methods
###################################

while True:
    registrar1 = None
    registrar2 = None
    _err, _results = grasp.get_flood(_asa_nonce, reg_obj)
    if not _err:
        # _results contains the returned locators if any       
        for x in _results:                
            # use whatever logic you want to decide which results to use.
            # For the demo code, we just pick one or two at random:
            grasp.tprint("Got", reg_obj.name, "at",
                         x.source.locator, x.source.protocol, x.source.port)
            if (not registrar1) and grasp._prng.randint(0,2):
                registrar1 = x.source
            elif grasp._prng.randint(0,2):
                if x.source != registrar1:
                    registrar2 = x.source
  

    else:
        grasp.tprint("get_flood failed", grasp.etext[_err])

    ###################################
    # Flood the chosen ones to neighbors
    ###################################
    
    if registrar1:
        #grasp.tprint("Floodout1")
        floodout(registrar1)
        if registrar2:
            #grasp.tprint("Floodout2")
            floodout(registrar2)

        ###################################
        # Listen for a pledge with timeout
        ###################################

        # Here, do the socket calls etc. to listen
        # for a BRSKI request from a pledge.
        # But for the demo, we just pretend...
        time.sleep(5)
        # simulate no request from pledge
        if grasp._prng.randint(0,2) == 0:
            grasp.tprint("No pledge contacted proxy")
        else:
            
            ###################################
            # BRSKI request received, now proxy it
            ###################################
            
            # Here, do the socket calls etc. to talk
            # to the registrar.
            # But for the demo, we just pretend...

            try:
                grasp.tprint("Pretending to contact registrar")
                # (socket calls etc)
                # simulate a random failure with a divide-by-zero
                _= 1/grasp._prng.randint(0,3)
                
            except:
                # Socket failure, we should mark this registrar as expired.
                grasp.tprint("Communication failed, expiring that registrar")
                
            ###################################    
            # Wait and loop back to find another registrar
            # and wait for another pledge.
            ###################################
    else:
        grasp.tprint("No registrar found, waiting to try again")

    time.sleep(18) # wait chosen to avoid synchronicity with Reggie
