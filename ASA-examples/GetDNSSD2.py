#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""########################################################
########################################################
# GetDNSSD2 is a demonstration Autonomic Service Agent.
# It supports the proposed GRASP objective family SRV.*
# in order to fetch and parse DNS-SD records on behalf of
# a client ASA
#
#
# See grasp.py for license, copyright, and disclaimer.
#
########################################################"""

import grasp
import ipaddress
import threading
import time
import sys
import cbor
import dns.resolver

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

####################################
# Support functions for negotiator
####################################

def endit(snonce, r):
    """Send end_negotiate with reason string"""
    grasp.tprint("Failed", r)
    err = grasp.end_negotiate(asa_nonce, snonce, False, reason=r)
    if err:
        grasp.tprint("end_negotiate error:",grasp.etext[err])
    

#resolver = dns.resolver.Resolver()
#resolver.timeout = 10
#resolver.lifetime = 10

def resolve(n,q):
    """Resolve a single domain and return the RR"""
    #grasp.tprint(resolver)
    try:
        grasp.ttprint("Resolving",n,q)
        a = dns.resolver.resolve(n,q)
        grasp.ttprint("Got",a)
        return a
    except:
        return []

def fix_string(s):
    """Replace escapes by raw bytes and return as a Unicode string"""
    r = ''
    while True:
        try:
            
            p1,p2 = s.split('\\', maxsplit=1)

            try:
                #replace escape sequence by byte
                ch = chr(int(p2[0:3]))
            except ValueError:
                #looks like an isolated backslash, not a Unicode escape
                #but we have to leave it in place for SRV lookup
                #to succeed
                ch='\\'+p2[0:3]
            r += p1 + ch
            s = p2[3:]
        except ValueError:
            r += s
            return str(bytes(r,encoding='raw_unicode_escape'),encoding='utf-8')

####################################
# Utility function to create a
# skeleton reply element
####################################

def new_relement():
    """-> skeleton reply element"""
    return {cp.outer:
            {cp.sender_loop_count: 15, #????
             cp.srv_element:
              {cp.msg_type: cp.describe,
               cp.service: None,
               cp.instance: None,
               cp.domain: None,
               cp.priority: 0,
               cp.weight: 0,
               cp.kvps: {},
               cp.clocator: []
              }
             }
            }
        

####################################
# Thread to handle a negotiation
####################################

class negotiator(threading.Thread):
    """Thread to negotiate objective as master"""
    def __init__(self, snonce, nobj):
        threading.Thread.__init__(self)
        self.snonce = snonce
        self.nobj = nobj

    def run(self):
        answer=self.nobj
        snonce=self.snonce
        
        answer.value, _cbor = detag(answer.value)
        if _cbor:
            grasp.tprint("CBOR value decoded")

        grasp.tprint("Got request")
        if answer.dry:
            endit(snonce,"Dry run not supported")
            return
        
        # Check format of request & extract fields
        try:
            req = answer.value.get("@rfcXXXX")
        except:
            req = None
        if not req:
            endit(snonce,"Not RFCXXXX format")
            return
        grasp.tprint(req)
        sel = req.get(cp.srv_element)
        if not sel:
            endit(snonce,"No service element")
            return     
        msg_type = sel.get(cp.msg_type)
        if msg_type != cp.describe_request:
            endit(snonce,"Not describe_request")
            return
        srv_name = sel.get(cp.service)
        if not srv_name:
            endit(snonce,"No service name")
            return
        dom_name = sel.get(cp.domain)
        if not dom_name:
            endit(snonce,"No domain name")
            return
        
        # Construct DNS name
        dns_name = "_"+srv_name+"."+dom_name
        if dns_name[-1] != ".":
            dns_name += "."

       
        #Look for PTR record first

        found_something = False
        broken = False
        a = resolve(dns_name,'PTR')
        
        for r in a:
            found_something = True
            #extract the instance name
            raw_name = str(r)
            #decode Unicode escapes
            fixed_name = fix_string(raw_name)
            #remove bogus escapes
            name = fixed_name.replace("\\","")
                            
            grasp.tprint("Got PTR name:",name)
            grasp.ttprint("Raw name:",raw_name)
            if name[-len(dns_name):] == dns_name:
                inst_name = name[0:-len(dns_name)-1]
            else:
                inst_name = name
            grasp.tprint("Instance name", inst_name)

            #start new reply element
            relement = new_relement()
            grasp.ttprint("Answer is", answer)
            relement[cp.outer][cp.sender_loop_count] = answer.loop_count
            relement[cp.outer][cp.srv_element][cp.instance] = inst_name
            relement[cp.outer][cp.srv_element][cp.service] = srv_name
            relement[cp.outer][cp.srv_element][cp.domain] = dom_name

            #look for other records
            a = resolve(fixed_name,'SRV')
            for r in a:
                grasp.ttprint("Got SRV", str(r))

                #parse SRV record to extract the fields

                priority,weight,srv_port,srv_dom = str(r).split(' ')
                grasp.ttprint("Got SRV domain", srv_dom)
                relement[cp.outer][cp.srv_element][cp.priority] = int(priority)
                relement[cp.outer][cp.srv_element][cp.weight] = int(weight)
                srv_port = int(srv_port)
                
                #look for address records & build locators
                loc_l = []
                a = resolve(srv_dom,'AAAA')
                for r in a:
                    grasp.ttprint("Got AAAA", str(r))
                    srv_addr = ipaddress.IPv6Address(r)
                    loc = [grasp.O_IPv6_LOCATOR,srv_addr.packed,17,srv_port]                    
                    loc_l.append(["Internet", loc])
                    
                a = resolve(srv_dom,'A')
                
                for r in a:
                    grasp.ttprint("Got A", str(r))
                    srv_addr = ipaddress.IPv4Address(r)
                    loc = [grasp.O_IPv4_LOCATOR,srv_addr.packed,17,srv_port]                    
                    loc_l.append(["Internet", loc])

                loc_l.append(["Internet",[grasp.O_FQDN_LOCATOR,srv_dom,17,srv_port]])

                #add locators to reply
                relement[cp.outer][cp.srv_element][cp.clocator] = loc_l
                
            a = resolve(name,'TXT')
            for r in a:
                grasp.tprint("Got TXT", r)                
                #Note that TXT records may include quotes
                try:
                    k,v = str(r).split(' ')
                    if k[0]=='"':
                        k=k[1:-1]
                    if v[0]=='"':
                        v=v[1:-1]                        
                    grasp.ttprint("kv",k,v)
                    relement[cp.outer][cp.srv_element][cp.kvps] = {k:v}
                except:
                    grasp.ttprint("Couldn't split", str(r))
                    pass

            # The relement is now complete, send it as next negotiation step

            grasp.tprint("Reply step", relement)
               
            answer.value = relement                  
            
            if _cbor:
                answer.value=cbor.dumps(answer.value)
            #send reply as negotiation step
            err,temp,answer = grasp.negotiate_step(asa_nonce, snonce, answer, 1000)
            grasp.ttprint("Negotiation step gave:", err, temp, answer)
            if (not err) and temp==None:
                grasp.tprint("Reply step succeeded")                 
            elif not err:
                answer.value, _ = detag(answer.value)
                if _:
                    grasp.tprint("CBOR value decoded")
                    
                if answer.value !="ACK":
                    grasp.tprint("Unexpected reply: loop count", answer.loop_count,
                                 "value",answer.value)
                    endit(snonce, "Unexpected reply")
                    broken = True
                    break
            else:    
                #other end rejected or loop count exhausted
                if err==grasp.errors.loopExhausted:
                    # we need to signal the end
                    endit(snonce, grasp.etext[err])
                else:
                    grasp.tprint("Failed:",grasp.etext[err])
                broken = True
                break
        #Sent all relements
        if broken:
            return
        if not found_something:
            #NXDOMAIN
            endit(snonce, "Service not found")
        else:
            err = grasp.end_negotiate(asa_nonce, snonce, True)
            if err:
                grasp.tprint("end_negotiate error:",grasp.etext[err])
                    

        #end of negotiation

grasp.tprint("==========================")
grasp.tprint("ASA GetDNSSD2 is starting up.")
grasp.tprint("==========================")
grasp.tprint("GetDNSSD2 is a demonstration Autonomic Service Agent.")
grasp.tprint("It runs indefinitely as a gateway to DNS,")
grasp.tprint("to fetch and parse SRV and related records,")
grasp.tprint("to proxy DNS-SD for GRASP nodes.")
grasp.tprint("It is implemented using a negotiation objective")
grasp.tprint("that can handle overlapping requests.")
grasp.tprint("On Windows or Linux, there should be a nice")
grasp.tprint("window that displays the process.")
grasp.tprint("==========================")

####################################
# General initialisation
####################################

#grasp.test_mode = True # set if you want detailed diagnostics
time.sleep(8) # so the user can read the text

####################################
# Register ASA/objective
####################################

err,asa_nonce = grasp.register_asa("GetDNSSD2")
if not err:
    grasp.tprint("ASA GetDNSSD2 registered OK")

else:
    exit()
    
obj1 = grasp.objective("SRV.")
obj1.loop_count = 4
obj1.neg = True


err = grasp.register_obj(asa_nonce,obj1)
if not err:
    grasp.tprint("Objective", obj1.name, "registered OK")
else:
    exit()

###################################
# Hack to get round nameservers that can't resolve the test domain
###################################

try:
    dns.resolver.resolve('_printer._sub._http._tcp.dns-sd.org.','PTR')
except:
    dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
    dns.resolver.default_resolver.nameservers = [ '2001:4860:4860::8888',
                                                  '2001:4860:4860::8844',
                                                  '8.8.8.8', '8.8.4.4' ]
    grasp.tprint("Couldn't resolve test domain, switched to Google nameservers")

###################################
# Set up pretty printing
###################################

grasp.init_bubble_text("GetDNSSD2")
grasp.tprint("GetDNSSD2 is listening")

###################################
# Negotiate as listener for ever
###################################

while True:
    # listen for negotiation request
    err, snonce, answer = grasp.listen_negotiate(asa_nonce, obj1)
    if err:
        grasp.tprint("listen_negotiate error:",grasp.etext[err])
        time.sleep(5) #to calm things if there's a looping error
    else:
        #got a new negotiation request; kick off a separate negotiator
        #so that multiple requests can be handled in parallel
        grasp.ttprint("Raw answer", answer.value)
        negotiator(snonce, answer).start()



