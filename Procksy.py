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

def floodout(registrar, method):
    
    r_addr = ipaddress.IPv6Address(registrar[1])
    r_port = registrar[3]
    grasp.tprint("Chose registrar", r_addr, r_port, method)
  
    ###################################
    # Finalise the proxy objective and locator
    ###################################
    
    proxy_obj.value = method
    proxy_locator.protocol = registrar[2]
    if method == "BRSKI-TCP":            
        proxy_locator.port = t_port
    elif method == "BRSKI-UDP":        
        proxy_locator.port = u_port
    else:
        return # unknown method
    
    ###################################
    # Flood it out for the pledges
    ###################################
    
    grasp.tprint("Flooding",proxy_obj.name, method)
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
grasp.tprint("This version corresponds to")
grasp.tprint("draft-carpenter-anima-ani-objectives-02")
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
# It's only used for synchronize so doesn't need to be filled in

reg_obj = grasp.objective("AN_join_registrar")
reg_obj.synch = True

####################################
# Create a TCP port for the proxy's communication
# with pledges
####################################

# For this demo, we just make up some numbers:

t_port = 11800 + grasp._prng.randint(0,5) #slightly random for demo
u_port = 11900 + grasp._prng.randint(0,5) #slightly random for demo

proxy_address = grasp.unspec_address # This is the unspecified address,
                                     # which signals link-local address to API
proxy_ttl = 60000 #milliseconds to live of the announcement

####################################
# Construct a correponding asa_locator
####################################

proxy_locator = grasp.asa_locator(proxy_address,0,False)
proxy_locator.is_ipaddress = True


####################################
# Construct the GRASP objective to announce the proxy
####################################

proxy_obj = grasp.objective("AN_join_proxy")
proxy_obj.synch = True
# proxy_obj.loop_count not set, the API forces it to 1 for link-local use
# proxy_obj.value to be filled in later

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

grasp.init_bubble_text("BRSKI Join Proxy (flooding method)")

###################################
# Now find the registrar and pick one or two methods
###################################

# Note - this is a simple version that simply takes the
# first registrar discovered. A more complex version
# would first use grasp.discover() and then synchronize
# with one or more discovered registrars.

while True:
    registrar1 = None
    method1 = None
    registrar2 = None
    _err, _result = grasp.synchronize(_asa_nonce, reg_obj, None, 1000)
    if not _err:
        # _result contains the returned objective
        grasp.tprint("Got",_result.name) #, ":", _result.value)
        for x in _result.value:
            # Extract the details (lazy code, no error checking)
            grasp.ttprint(x[0],ipaddress.IPv6Address(x[1][1]), x[1][2], x[1][3])

            if x[0] == "BRSKI-IPIP":
                grasp.tprint("IP-in-IP available at",
                             ipaddress.IPv6Address(x[1][1]))
                
            # use whatever logic you want to decide which results to flood.
            # For the demo code, we just pick one or two at random:

            elif (not registrar1) and grasp._prng.randint(0,2):
                registrar1 = x[1]
                method1 = x[0]
            elif grasp._prng.randint(0,2):
                if x[0] != method1:
                    registrar2 = x[1]
                    method2 = x[0]

    else:
        grasp.tprint("synchronize failed", grasp.etext[_err])

    ###################################
    # Flood the chosen ones to neighbors
    ###################################
    
    if registrar1:
        #grasp.tprint("Floodout1")
        floodout(registrar1,method1)
        if registrar2:
            #grasp.tprint("Floodout2")
            floodout(registrar2,method2)

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
                grasp.tprint("Contacting registrar")
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

    time.sleep(18) # wait chosen to avoid synchronicity with Reggie
