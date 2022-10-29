#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Demo MUD manager using GRASP. See grasp.py for license, copyright, and disclaimer."""

###################################################
###################################################
# The code attempts to find a MUD certificate store
# (which may be created by Mudvault.py)
# If that fails, patch in here the full path of the
# CA file (a PEM file) or the CA directory path.
# DO NOT set both CAfile and CApath.
###################################################
# CAfile = '<your CA file path here>'
# CApath = '<your CA directory path here>'
###################################################
# Typical location for CAfile on Windows is
# C:/OpenSSL-Win64/certs/mud-certs.pem
###################################################

import grasp
import threading
import time
import ipaddress
import requests
import json
import os
from subprocess import run


###################################
# Print obj_registry and flood cache
###################################

def dump_some():
    """Dumps some GRASP internals for debugging."""
    grasp.tprint("Objective registry contents:")         
    for x in grasp._obj_registry:
        o= x.objective
        grasp.tprint(o.name,"ASA:",x.asa_id,"Listen:",x.listening,"Neg:",o.neg,
               "Synch:",o.synch,"Count:",o.loop_count,"Value:",o.value)
    grasp.tprint("Flood cache contents:")            
    for x in grasp._flood_cache:
        grasp.tprint(x.objective.name,"count:",x.objective.loop_count,"value:",
                     x.objective.value,"source",x.source)
    time.sleep(5)

###################################
# Support function
###################################

def no_CAfile(msg):
    """Support function for CAfile discovery failure"""
    print(msg)
    print("You need to set CAfile or CApath in the")
    print("source code. Sorry about the hack.")
    time.sleep(10)
    exit()
    

###################################
# Check MUD signature (via a call
# out to OpenSSL)
###################################

cwd = os.getcwd().replace('\\','/')

def check_sig(j,sig):
    """ j is the MUD file (JSON) to be validated,
        sig is the URL of the signature file,
        return True if verified, else False."""
    mfile = cwd+"/mud.mud"
    file = open(mfile, "wb")
    file.write(j)
    file.close()
    try:
        pfile = cwd+"/p7s.p7s"
        p7s = requests.get(sig).content
        file = open(pfile, "wb")
        file.write(p7s)
        file.close()
    except:
        grasp.tprint("Couldn't fetch signature file")
        return False
    cmd = ['openssl', 'cms', '-verify', '-in',
            pfile, '-inform', 'DER', '-content',
            mfile, '-binary']
    if 'CAfile' in globals():
        cmd.append('-CAfile')
        cmd.append(CAfile)
    elif 'CApath' in globals():
        cmd.append('-CApath')
        cmd.append(CApath)
    x = run(cmd)
    grasp.ttprint(x)
    try:
        os.remove(mfile)
        os.remove(pfile)
    except:
        pass
    if x.returncode != 0:
        return False
    else:
        return True


####################################
# Support functions for negotiator
####################################

def endit(snonce, r):
    """Crash out of a negotiation"""
    grasp.tprint("Failed", r)
    err = grasp.end_negotiate(asa_nonce, snonce, False, reason=r)
    if err:
        grasp.tprint("end_negotiate error:",grasp.etext[err])

def process_MUD_URL(url):
    """Process a MUD URL"""
    grasp.tprint("Processing MUD URL now")
    try:
        k = requests.get(answer.value).content
        j = json.loads(k.decode())
    except:                
        grasp.tprint("Faulty URL or faulty JSON")
        return #from thread
    #got valid JSON, now do some example parsing
    try:
        grasp.tprint(j['ietf-mud:mud']['last-update'],j['ietf-mud:mud']['systeminfo'])
    except:
        grasp.tprint("Faulty MUD file")
        return #from thread
    try:
        sig = j['ietf-mud:mud']['mud-signature']
    except:
        grasp.tprint("Warning: unsigned MUD file")
        return #from thread
    grasp.tprint("Signature at",sig)
    if check_sig(k, sig):
        grasp.tprint("Signature verified")
    else:
        grasp.tprint("Signature invalid")

####################################
# Thread to handle a MUDURL negotiation
####################################

class negotiator(threading.Thread):
    """Thread to negotiate MUDURL as MUD manager"""
    def __init__(self, snonce, nobj):
        threading.Thread.__init__(self)
        self.snonce = snonce
        self.nobj = nobj

    def run(self):
        answer=self.nobj
        snonce=self.snonce        
        grasp.ttprint("listened, answer",answer.name, answer.value)
        grasp.tprint("Got MUD URL", answer.value,
                     "from", ipaddress.IPv6Address(snonce.id_source))
        if grasp.tname(answer.value)!="str":
            endit(snonce, "Not a string")
        elif answer.value[0:8]!="https://":
            endit(snonce, "Not https: scheme")
        #could do other sanity checks
        else:
            #sanity checks passed
            #Now the MUD manager can process the URL
            process_MUD_URL(answer.value)            

            #close the session normally (with no feedback to peer)
            err = grasp.end_negotiate(asa_nonce, snonce, True)
            if err:
                grasp.tprint("end_negotiate error:",grasp.etext[err])       
         #end of a negotiating session

####################################
# Main program starts here
####################################

# Check OpenSSL status

try:
    run(['openssl', 'exit'])
except:
    print('OpenSSL is not in the system path.')
    print('Due to the inadequate OpenSSL support in')
    print('Python, you need to install OpenSSL and')
    print('add it to the system path, probably followed')
    print('by a system restart. Goodbye.')
    time.sleep(10)
    exit()

# Find MUD cert file if needed

if (not 'CAfile' in globals()) and (not 'CApath' in globals()):
    if os.name == 'nt':
        syspath = os.environ['PATH']
        if 'OpenSSL' in syspath:
            syspath = syspath.replace('\\','/')
            head,tail = syspath.split('OpenSSL', maxsplit=1)
            _,_,head = head.rpartition(';')
            tail,_ = tail.split('/', maxsplit=1)
            CAfile = head+'OpenSSL'+tail+"/certs/mud-certs.pem"
            if not os.path.exists(CAfile):
                no_CAfile("Cannot find "+CAfile)        
        else:
            no_CAfile("Cannot find OpenSSL directory")
    else: #assume Linux
        CAfile = '/etc/ssl/certs/mud-certs.pem'
        if not os.path.exists(CAfile):
            no_CAfile("Cannot find "+CAfile)
 

grasp.tprint("==========================")
grasp.tprint("ASA Mudlark is starting up.")
grasp.tprint("==========================")
grasp.tprint("Mudlark is a demonstration Autonomic Service Agent.")
grasp.tprint("It simulates a Network Management System function")
grasp.tprint("that receives MUD URLs from joining nodes and")
grasp.tprint("acts as a MUD manager per RFC8520.")
grasp.tprint("On Windows or Linux, there should be a nice window")
grasp.tprint("that displays the process.")
grasp.tprint("==========================")

#grasp.test_mode = True # set if you want detailed diagnostics
time.sleep(8) # so the user can read the text

####################################
# Register ASA/objectives
####################################

asa_name = "Mudlark"
err,asa_nonce = grasp.register_asa("asa_name")
if not err:
    grasp.tprint("ASA",asa_name, "registered OK")
else:
    grasp.tprint("ASA registration failure:", grasp.etext[err])
    time.sleep(60)
    exit()

obj_name = "411:MUDURL"
obj3 = grasp.objective(obj_name)
obj3.neg = True

err = grasp.register_obj(asa_nonce,obj3)
if not err:
    grasp.tprint("Objective", obj_name, "registered OK")
else:
    grasp.tprint("Objective registration failure:", grasp.etext[err])
    time.sleep(60)
    exit()

if grasp.test_mode:
    dump_some()


###################################
# Negotiate MUDURL as listener for ever
###################################

grasp.init_bubble_text(asa_name)
grasp.tprint("Ready to negotiate", obj_name, "as listener")

while True:    
    #listen for new negotiation
    err, snonce, answer = grasp.listen_negotiate(asa_nonce, obj3)
    if err:
        grasp.tprint("listen_negotiate error:",grasp.etext[err])
        if grasp.test_mode:
            dump_some()
        time.sleep(5) #to calm things if there's a looping error
    else:
        #got a new negotiation request; kick off a separate negotiator
        #so that multiple requests can be handled in parallel
        negotiator(snonce, answer).start()

