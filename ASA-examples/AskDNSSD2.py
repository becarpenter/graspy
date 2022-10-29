#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""########################################################
########################################################
# AskDNSSD is a demonstration Autonomic Service Agent.
# It supports the proposed GRASP objective family SRV.*
# in order to request DNS-SD records from a server ASA
#
#
# See grasp.py for license, copyright, and disclaimer.
#                                                     
########################################################"""

import grasp
import time
import cbor #2 as cbor
import ipaddress


###################################
# Support function for CBOR coded
# objective value
###################################

def detag(val):
    """ Decode CBOR if necessary
        -> decoded_object, was_CBOR"""
    try:
        return cbor.loads(val), True
    except:
        try:
            if val.tag == 24:
                return cbor.loads(val.value), True
        except:
            return val, False

###################################
# Constants for building dicts
###################################

class codepoints:
    """Code points for objective dictionaries"""
    def __init__(self):
        self.sender_loop_count = 1
        self.srv_element = 2
        
        self.private = 0
        self.msg_type = 1
        self.service = 2
        self.instance = 3
        self.domain = 4
        self.priority = 5
        self.weight = 6
        self.kvps = 7
        self.net_range = 8
        self.clocator = 9

        self.describe = 0
        self.describe_request = 1
        self.enumerated = 2
        self.enumerated_request = 3

        self.outer = "@rfcXXXX"

cp = codepoints()

####################################
# Utility function to create a
# skeleton rerequest element
####################################

def new_relement():
    """-> skeleton request element"""
    return {cp.outer:
            {cp.sender_loop_count: grasp.GRASP_DEF_LOOPCT,
             cp.srv_element:
              {cp.msg_type: cp.describe_request,
               cp.service: None,
               cp.instance: None,
               cp.domain: None,
               cp.priority: 0,
               cp.weight: 0,
               cp.kvps: {},
               cp.clocator: None
              }
             }
            }

####################################
# Utility function to prettify
# a relement
####################################

def prettify(r):
    try:
        locs = r[cp.outer][cp.srv_element][cp.clocator]

        for i in range(len(locs)):
            if locs[i][1][0] == grasp.O_IPv6_LOCATOR:
                locs[i][1][1] = str(ipaddress.IPv6Address(locs[i][1][1]))
            elif locs[i][1][0] == grasp.O_IPv4_LOCATOR:
                locs[i][1][1] = str(ipaddress.IPv4Address(locs[i][1][1]))

        r[cp.outer][cp.srv_element][cp.clocator] = locs
    except:
        pass
    return r


###################################
# Function to negotiate as initiator
# to get DNS records
###################################

def get_dns_info(service, dom):
    """Obtain and return all DNS-SD records for a service and domain"""
    global obj3
    global failct
    #start of a negotiating session

    obj3.loop_count = 20 #allows for some fragmentation
    obj3.dry = False     #dry run not allowed
    
    req_elem = new_relement()
    req_elem[cp.outer][cp.sender_loop_count] = obj3.loop_count
    req_elem[cp.outer][cp.srv_element][cp.service] = service
    req_elem[cp.outer][cp.srv_element][cp.domain] = dom
    
    obj3.value = req_elem
    


    # As a random test, use CBOR (Tag 24) format for value (should work)
    if not grasp._prng.randint(0,3):
        _cbor = True 
    else:
        _cbor = False   
        
    grasp.tprint("Asking for",obj3.value,"; Tag 24",_cbor)
    
    #discover a peer
    if failct > 3:
        failct = 0
        grasp.tprint("Flushing", obj3.name, "discovery")
        _, ll = grasp.discover(asa_nonce, obj3, 1000, flush = True)
    else:
        _, ll = grasp.discover(asa_nonce, obj3, 1000)
    if ll==[]:
        grasp.tprint("Discovery failed")
        failct += 1
        return
  
    grasp.ttprint("Discovered locator", ll[0].locator)
    
    #attempt to negotiate
    
    if _cbor:
        #CBORise the value
        obj3.value=cbor.dumps(obj3.value)

    reply = []
    err, snonce, answer = grasp.req_negotiate(asa_nonce, obj3, ll[0], None)
    if err:
        if err==grasp.errors.declined and answer!="":
            _e = answer
        else:
            _e = grasp.etext[err]
        grasp.tprint("req_negotiate error:", _e)
        failct += 1
        grasp.tprint("Fail count", failct)
        time.sleep(5) #to calm things if there's a looping error
    elif (not err) and snonce:
        grasp.ttprint("requested, session_nonce:",snonce,"answer",answer)
        _found_cbor = False
        if _cbor:
            answer.value, _found_cbor = detag(answer.value)

        grasp.tprint("First reply:",prettify(answer.value))
            
        if _cbor != _found_cbor:
            #Anomaly, get me out of here
            grasp.tprint("CBOR anomaly 1 - missing segment?")
            grasp.end_negotiate(asa_nonce, snonce, False,
                                reason="CBOR anomaly 1 - missing segment?")                   
        else:
            #Received first answer
            looping = True
            while looping:               
                #need to go again                
                answer.value = "ACK"
                grasp.tprint("Sending ACK for more")
                answer.loop_count += 2 #allow an extra round trip
                if _cbor:
                    #CBORise the value
                    answer.value=cbor.dumps(answer.value)                
                err,temp,answer = grasp.negotiate_step(asa_nonce, snonce, answer, 5000)
                if err:
                    grasp.tprint("negotiate_step error:",grasp.etext[err])
                    looping = False
                elif not temp:
                    #end of replies
                    looping = False
                else:
                    if _cbor:
                        answer.value, _found_cbor = detag(answer.value)
                        if _cbor != _found_cbor:
                            #anomaly, get me out of here
                            looping = False
                            grasp.end_negotiate(asa_nonce, snonce, False,
                                                reason="CBOR anomaly 2 - missing segment?")
                            grasp.tprint("CBOR anomaly 2 - missing segment?")
                            return
                    grasp.tprint("Next reply:", prettify(answer.value))
        grasp.tprint("End of replies")
    else:
        #immediate end, strange        
        grasp.tprint("Unexpected reply", answer.value)
        

    #end of a negotiating session
    time.sleep(5) #to keep things calm...
    return

grasp.tprint("========================")
grasp.tprint("ASA AskDNSSD2 is starting up.")
grasp.tprint("========================")
grasp.tprint("AskDNSSD2 is a demonstration Autonomic Service Agent.")
grasp.tprint("It acts as a client, asking for DNS-SD information.")
grasp.tprint("On Windows or Linux, there should be a nice window")
grasp.tprint("that displays the process.")
grasp.tprint("========================")

####################################
# General initialisation
####################################

#grasp.test_mode = True # tell everybody it's a test
time.sleep(8) # so the user can read the text
failct = 0    # fail counter to control discovery retries

####################################
# Register ASA/objectives
####################################

err, asa_nonce = grasp.register_asa("AskDNSSD2")
if not err:
    grasp.tprint("ASA AskDNSSD2 registered OK")
else:
    exit()

#This objective is for the negotiating test
obj3 = grasp.objective("SRV.")
obj3.neg = True


err = grasp.register_obj(asa_nonce,obj3)
if not err:
    grasp.tprint("Objective", obj3.name, "registered OK")
else:
    exit()
    

###################################
# Set up pretty printing
###################################         


grasp.init_bubble_text("AskDNSSD2")
grasp.tprint("Ready to negotiate", obj3.name,"as requester")



#main loop
while True:
    #insert test cases here
    get_dns_info('sip._udp.sip','voice.google.com')
    #get_dns_info('dmarc','gmail.com')
    #get_dns_info('http._tcp','dns-sd.org')
    #time.sleep(5)
    get_dns_info('printer._sub._http._tcp','dns-sd.org.')
    time.sleep(5)
    get_dns_info('http._tcp','dns-sd.org.')
    time.sleep(5)

    
