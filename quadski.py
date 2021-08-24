#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""########################################################
########################################################
# quadski is an Autonomic Service Agent.
# It supports the unregistered GRASP objectives 411:quadskip
# and 411:quadski in order to securely send QUADS keys to a
# pledge ASA.
#
# See grasp.py for license, copyright, and disclaimer.
#
########################################################"""

import grasp
import threading
import time
import cbor
import os
import getpass

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

####################################
# Thread to flood the objective repeatedly
####################################

class flooder(threading.Thread):
    """Thread to flood objectve repeatedly"""
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        while True:         
            grasp.flood(asa_nonce, 120000,
                        grasp.tagged_objective(flood_obj,None))
            time.sleep(60)


####################################
# Support function for negotiator
####################################

def endit(snonce, r):
    """Send end_negotiate with reason string"""
    grasp.tprint("Failed", r)
    err = grasp.end_negotiate(asa_nonce, snonce, False, reason=r)
    if err:
        grasp.tprint("end_negotiate error:",grasp.etext[err])      

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
        received_obj=self.nobj
        snonce=self.snonce    
        grasp.tprint("Got request for QUADS keys")
        if received_obj.dry:
            endit(snonce,"Dry run not supported")
        else:
            #unwrap pledge's request                            
            pledge_password = private_key.decrypt(
                         received_obj.value[0],
                         padding.OAEP(
                         mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(),
                         label=None))
            if pledge_password != password:
                endit(snonce,"Incorrect password")
            else:
                #prepare pledge's public key
                pub_key = serialization.load_pem_public_key(
                    received_obj.value[1],
                    backend=default_backend() )
                #prepare the QUADS keys
                chunk = cbor.dumps([key, iv])
                grasp.tprint("Sending keys")
                #encrypt chunk
                received_obj.value = pub_key.encrypt(
                    chunk,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None))
                grasp.ttprint("Sending",len(chunk),"bytes")
                                                          
                #send keys as negotiation step                    
                err,temp,received_obj = grasp.negotiate_step(asa_nonce, snonce, received_obj, 1000)
                grasp.ttprint("Negotiation step gave:", err, temp, received_obj)
                if not err:
                    # the other end signalled End/Accept
                    grasp.tprint("Ended transfer")                 
                else:    
                    #other end rejected or loop count exhausted
                    if err==grasp.errors.loopExhausted:
                        # we need to signal the end
                        endit(snonce, grasp.etext[err])
                    else:
                        grasp.tprint("Failed:",grasp.etext[err])
                        

        #end of negotiation

###################################
# Get the keys
###################################
try:
    import quadskMaster
    key = quadskMaster.key
    iv = quadskMaster.iv
except:
    #print("No master keys found, looking for local keys")
    try:
        import quadsk
        key = quadsk.key
        iv = quadsk.iv
    except:
        print("No keys found, goodbye")
        time.sleep(10)
        exit()

grasp.tprint("==========================")
grasp.tprint("QUADS key infrastructure is starting up.")
grasp.tprint("==========================")

###################################
# Get the domain pledge password
###################################

print("Please enter the password that pledges will use to join the domain.")
password =0
confirm = 1
while password != confirm:
    password = bytes(getpass.getpass(), 'utf-8')
    confirm = bytes(getpass.getpass("Confirm: "), 'utf-8')      
    if password != confirm:
        print("Mismatch, try again.")


####################################
# General initialisation
####################################

#time.sleep(8) # so the user can read the text

#this instance of GRASP must run unencrypted
grasp.skip_dialogue(selfing=True,quadsing=False)

#grasp.tprint("Encryption", grasp.crypto, "(should be False)")

####################################
# Register ASA/objectives
####################################

err,asa_nonce = grasp.register_asa("quadski")
if not err:
    grasp.tprint("ASA quadski registered OK")

else:
    exit()
    
keys_obj = grasp.objective("411:quadski")
keys_obj.loop_count = 4
keys_obj.neg = True
#The pledge sends the [encrypted_domain_password, pledge_PEM] as the
#value of this objective, as a list of bytes objects. The password is
#RSA encrypted with quadski's public key.

#quadski sends the key bytes and iv (initialisation vector) bytes
#file as the return value of this objective, as an array [key, iv]
#encoded in CBOR and then encrypted with the pledge's public key.

err = grasp.register_obj(asa_nonce,keys_obj)
if not err:
    grasp.tprint("Objective", keys_obj.name, "registered OK")
else:
    exit()

flood_obj = grasp.objective("411:quadskip")
flood_obj.loop_count = 4
flood_obj.synch = True
#The value of this objective is the quadski public key PEM string

err = grasp.register_obj(asa_nonce,flood_obj)
if not err:
    grasp.tprint("Objective", flood_obj.name, "registered OK")
else:
    exit()





###################################
# Set up pretty printing
###################################

grasp.init_bubble_text("QUADSKI Server")
grasp.tprint("QUADSKI is operational")

###################################
# Make a key pair for quadski
###################################

private_key = rsa.generate_private_key(
     public_exponent=65537,
     key_size=2048,
     backend=default_backend() )
public_key = private_key.public_key()
my_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo )

###################################
# Start flooding out the public key
###################################

flood_obj.value = my_pem
flooder().start()
grasp.tprint("Flooding", flood_obj.name, "for ever")

###################################
# Negotiate as listener for ever
###################################

while True:
    #grasp.tprint("Encryption", grasp.crypto, "(should be False)")
    # listen for negotiation request
    err, snonce, request = grasp.listen_negotiate(asa_nonce, keys_obj)
    if err:
        grasp.tprint("listen_negotiate error:",grasp.etext[err])
        time.sleep(5) #to calm things if there's a looping error
    else:
        #got a new negotiation request; kick off a separate negotiator
        #so that multiple requests can be handled in parallel
        negotiator(snonce, request).start()



