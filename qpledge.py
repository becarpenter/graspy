#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""########################################################
########################################################
# qpledge is an Autonomic Service Agent.
# It supports the unregistered GRASP objectives 411:quadskip
# and 411:quadski in order to request QUADS keys from a quadski ASA,
# thereby enrolling the pledge node in the QUADS domain
#
# See grasp.py for license, copyright, and disclaimer.
#
########################################################"""


import os
import subprocess
import sys
##if os.name!="nt":
##    sys.path.append('IETF stuff/anima/graspy')

import grasp
import time
import cbor
import getpass

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

###################################
# Function to input password
###################################

def get_pass():
    global password
    print("Please enter the pledge password for the domain.")
    password =0
    confirm = 1
    while password != confirm:
        password = bytes(getpass.getpass(), 'utf-8')
        confirm = bytes(getpass.getpass("Confirm: "), 'utf-8')      
        if password != confirm:
            print("Mismatch, try again.")
            
###################################
# Function to negotiate as initiator
# to get QUADS keys
###################################

def get_file():
    """Get key file"""
    global keys_obj
    global failct
    global private_key

    #look for quadski

    err, results = grasp.get_flood(asa_nonce, flood_obj)
    if not err:
        # results contains all the unexpired tagged objectives
        # but really there should only be one...     
        if results == []:
            grasp.tprint("Found no value for",flood_obj.name)
            time.sleep(10) #pause for something to change...
            return
        else:
            grasp.tprint("Found value for",flood_obj.name)
        # recover quadski's public key
        quadski_pub_key = serialization.load_pem_public_key(
        results[0].objective.value,
        backend=default_backend() )
    else:
        grasp.tprint("get_flood failed", grasp.etext[err])
        return #not this time

    #set up objective value
    ciphertext = quadski_pub_key.encrypt(
                    password,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None))
    keys_obj.value = [ciphertext,pem] 
    
    #start of negotiating session
    grasp.tprint("Asking for keys")
    
    #discover a peer
    if failct > 3:
        failct = 0
        grasp.tprint("Flushing", keys_obj.name, "discovery")
        _, ll = grasp.discover(asa_nonce, keys_obj, 1000, flush = True)
    else:
        _, ll = grasp.discover(asa_nonce, keys_obj, 1000)
    if ll==[]:
        grasp.tprint("Discovery failed")
        failct += 1
        return
  
    grasp.ttprint("Discovered locator", ll[0].locator)
    
    #attempt to negotiate
    
    err, snonce, received_obj = grasp.req_negotiate(asa_nonce, keys_obj, ll[0], 5000)
    if err:
        if err==grasp.errors.declined and received_obj!="":
            _e = received_obj
        else:
            _e = grasp.etext[err]
        grasp.tprint("Negotiation error:", _e)
        failct += 1
        grasp.tprint("Fail count", failct)
        if _e == "Incorrect password":
            get_pass()
            return 
    elif (not err) and snonce:
        grasp.ttprint("requested, session_nonce:",snonce,"received_obj",received_obj)
        grasp.ttprint("Received raw reply",received_obj.value)
        grasp.ttprint("received_obj is", received_obj.value)
        if received_obj.value == b'':
            grasp.tprint("Keys not found")
        else:
            grasp.ttprint("Starting transfer")
            #decrypt block
            plaintext = private_key.decrypt(
                     received_obj.value,
                     padding.OAEP(
                     mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None))
            keys = cbor.loads(plaintext)
            key = keys[0]
            iv = keys[1]
            file = open(r"quadsk.py","w")
            file.write("key="+str(key)+"\n")
            file.write("iv="+str(iv)+"\n")
            file.close()
            grasp.tprint("quadsk.py saved OK")
            err = grasp.end_negotiate(asa_nonce, snonce, True)
            if err:
                grasp.tprint("end_negotiate error:",grasp.etext[err])                   
    else:
        #immediate end, strange        
        grasp.tprint("Unexpected reply", received_obj.value)

    #end of a negotiating session
    time.sleep(10) #pause for something to change...
    return

###################################
# Utility function
###################################

def in_idle():
    try:
        return sys.stdin.__module__.startswith('idlelib')
    except AttributeError:
        return False

grasp.tprint("========================")
grasp.tprint("QUADS pledge is starting up.")
grasp.tprint("========================")

get_pass()

try:
    os.remove("quadsk.py")
    grasp.tprint("Removed old key file")
except:
    pass

####################################
# General initialisation
####################################

grasp.skip_dialogue(selfing=True)
failct = 0    # fail counter to control discovery retries

####################################
# Make key pair for the pledge
####################################

private_key = rsa.generate_private_key(
     public_exponent=65537,
     key_size=2048,
     backend=default_backend() )
public_key = private_key.public_key()
pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo )

####################################
# Register ASA/objectives
####################################

err, asa_nonce = grasp.register_asa("qpledge")
if not err:
    grasp.tprint("QUADS pledge registered OK")
else:
    exit()

flood_obj = grasp.objective("411:quadskip")
flood_obj.loop_count = 4
flood_obj.synch = True
#The value of this objective is the quadski public key PEM

keys_obj = grasp.objective("411:quadski")
keys_obj.neg = True
keys_obj.loop_count = 4
#The pledge sends the [encrypted_domain_password, pledge_PEM] as the
#value of this objective, as a list of bytes objects. The password is
#RSA encrypted with quadski's public key.

#quadski sends the key bytes and iv (initialisation vector) bytes
#file as the return value of this objective, as an array [key, iv]
#encoded in CBOR and then encrypted with the pledge's public key

err = grasp.register_obj(asa_nonce,keys_obj)
if not err:
    grasp.tprint("Objective", keys_obj.name, "registered OK")
else:
    exit()
    

###################################
# Set up pretty printing
###################################         


grasp.init_bubble_text("QUADS Pledge")
grasp.tprint("Ready to negotiate", keys_obj.name,"as requester")


###################################
# Main loop
###################################

get_file()
while not os.path.isfile("quadsk.py"):
    get_file()
    
grasp.tprint("Installed new key file")

if grasp._relay_needed:
    grasp.tprint("This is a relay node - launching encrypted GRASP daemon")
    try:
        subprocess.Popen(['python3', 'gremlina.py'])
    except:            
        subprocess.Popen(['python', 'gremlina.py'])
    grasp.tprint("Remaining active as an unencrypted GRASP daemon")
    while True:
        time.sleep(60)
else:
    if in_idle():
        grasp.tprint("Not a relay node")
    else:
        grasp.tprint("Not a relay node, will exit in one minute")
    time.sleep(60)
    sys.exit()
