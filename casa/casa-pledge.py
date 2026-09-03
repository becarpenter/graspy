#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""This is a proof-of-concept BRSKI proxy for the CASA suite.
It finds a BRSKI proxy, using GRASP per RFC8995. It then performs
BRSKI onboarding using a previously loaded CASA ODevID in place
of a regular IDevID.
"""

# Released under the BSD "Revised" License.
#                                                     
# Copyright (C) 2026 Brian E. Carpenter.                  
# All rights reserved.

# 20260903 First version

import sys
sys.path.insert(0, '..') # in case graspi.py is one level up
import graspi
import threading
import time
import socket
import requests
import secrets
import ssl
import json
import os
from base64 import b64encode as b64e
from base64 import b64decode as b64d
import ipaddress
from casa_odevid import parse_idevid
import warnings
warnings.filterwarnings("ignore", module="urllib3") # ignore self-signed warning

from casa_setup import *

# set up file names

fpath = env_path + "/pledge"
key_file = fpath + "/odevid_key.pem"
cert_file = fpath + "/odevid_cert.pem"
eec_file = fpath + "/end_entity_cert.pem"
voucher_file = fpath + "/voucher.json"
ca_file = fpath + "/cacert.pem"
domain_cert_file = fpath + "/domain_cert.pem"

# check if ODevID exists

if not os.path.exists(cert_file):
    crash("No ODevID exists. No action taken")

# check if pledge already registered

yes = input("Test mode (ignores existing voucher) Y/N:")
if not (yes.startswith("y") or yes.startswith("Y")):
    if os.path.exists(voucher_file):
        crash("Voucher already exists.  No action taken.") 

# acquire pledge's own certificate and key

cert_pem_bytes = open(cert_file, "rb").read()
#key_pem_bytes  = open(key_file, "rb").read()

###################################
# Map protocols to method names
###################################
pm={socket.IPPROTO_UDP: "UDP",
    socket.IPPROTO_TCP: "TCP",
    socket.IPPROTO_IPV6: "IPIP"}

###################################
# Failure handler
###################################
ok = True

def fail(*msg):
    global ok
    ok = False
    graspi.tprint(*msg)

###################################
# HTTP calls
###################################

# Thes calls rely on a pre-existing PKI, since
# the ODevID is self-signed and cannot satisfy TLS
# verification reuqirements

def try_post(url, jso):
    try:
        return(requests.post(url, json=jso, headers=myhdrs,
                             verify=False, timeout=5))
    except Exception as e:
        graspi.tprint("POST fail "+str(e))
        return(None)    

def try_get(url):
    try:
        return(requests.get(url, verify=False, timeout=5))
    except Exception as e:
        graspi.tprint("GET fail "+str(e))
        return(None) 
    
###################################
# Main thread starts here
###################################

# Note: silent=True will suppress all GRASP printing
graspi.skip_dialogue(selfing=True, be_dull=True, figging=False) #, silent=True)

graspi.tprint("CASA pledge is starting up.")

####################################
# Register this ASA
####################################

# The ASA name is arbitrary - it just needs to be
# unique in the GRASP instance.

_err,_asa_nonce = graspi.register_asa("CASA-pledge")
if not _err:
    graspi.tprint("CASA-pledge registered OK")
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

graspi.tprint("Pledge starting now")

###################################
# Now find the proxy(s)
###################################

proxy = None

while not proxy:
    graspi.tprint("Waiting for proxy")
    time.sleep(20)   # arbitrary wait
    err, results = graspi.get_flood(_asa_nonce, proxy_obj)
    if (not err) and len(results):
        # results contains all the unexpired tagged objectives
        graspi.tprint("Found",len(results),"result(s)")
        # Use the first one (lazy code)
        proxy = results[0]
        # Extract the details
        try:
            proxy.method = pm[proxy.source.protocol]
        except:
            proxy.method = "Unknown"                 
    elif err:
        graspi.tprint("get_flood failed", graspi.etext[_err])

    if not proxy:
        continue

    ok = True
    p_addr = proxy.source.locator
    p_ifi  = proxy.source.ifi
    p_proto = proxy.source.protocol
    p_port = proxy.source.port
    p_method = proxy.method
    host = str(p_addr)
    hostz = str(p_addr)+"%"+str(p_ifi) #add zone ID
    graspi.tprint("Found proxy at", hostz,
                  "protocol", p_proto, "port", p_port, "method", p_method)    

    if p_method != "TCP":
        fail("Unsupported method ", p_method)
        # This proxy is no good
        proxy = None
        continue
    
    ###################################
    # Connect to the proxy
    ###################################
    
    graspi.tprint("Preparing to contact proxy")

    # Prepare voucher request

    parsed = parse_idevid(cert_pem_bytes)
    req = {ivrv:
        {"assertion": "proximity"
         }}
    nonce = secrets.token_bytes(nonce_l).hex()
    req[ivrv]["nonce"] = nonce
    req[ivrv]["serial-number"] = parsed["serial-number"]
    req[ivrv]["idevid-issuer"] = parsed["idevid-issuer"]
    req[ivrv]["created-on"] = timestamp()
    
    try:
    
        # Get end-entity certficate of registrar, using ODevID credentials
        
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False       # Disable hostname matching
        context.load_cert_chain(cert_file, keyfile=key_file)
        context.verify_mode = ssl.CERT_NONE  # Disable certificate verification
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.connect((host, p_port, 0, p_ifi))
        secure_s = context.wrap_socket(s, server_hostname=host)
        ee_cert = secure_s.getpeercert(binary_form=True)
        secure_s.close()

        graspi.tprint("Obtained end-entity cert")

        # save end-entity cert in PEM format
        with open(eec_file, "w") as f:
            f.write(ssl.DER_cert_to_PEM_cert(ee_cert))
        ee_cert_bytes = open(eec_file, "rb").read()

        #ee_cert =b'crap' # uncomment to test mismatch

        # Add end-entity cert to voucher request
        req[ivrv]["proximity-registrar-cert"] = b64e(ee_cert).decode("utf-8")

        # Add pledge-cert to voucher request
        req[ivrv]["pledge-self-cert"] = b64e(cert_pem_bytes).decode("utf-8")

        # CMS-sign voucher request with ODevID key

        signed_req = sign_json(req, cert_file, key_file, fpath)
        
        # Prepare HTTP environment

        myhdrs = {"Content-Type": "application/voucher-cms+json"}
        base_url = "https://["+hostz+"]:"+str(p_port)+"/.well-known/"

        #graspi.tprint("Base URL", base_url)

        # Issue request & process result
        res = try_post(base_url+"brski/requestvoucher", b64e(signed_req).decode("utf-8"))
        if res==None:
            fail("Failure on requestvoucher")
        elif res.status_code == 200:
            signed_voucher = b64d(res.content).decode("utf-8")
            voucher = verify_json(signed_voucher, fpath)

            if not voucher:
                fail("Voucher signature fault")
            elif voucher[ivv]["nonce"] != nonce:
                fail("Nonce mismatch")
            elif voucher[ivv]["serial-number"] != parsed["serial-number"]:
                fail("Serial number mismatch")
            elif voucher[ivv]["assertion"] != "logged":
                fail("Not logged")
            elif not "pinned-domain-cert" in voucher[ivv]:
                fail("No domain certificate")
            else:
                graspi.tprint("Voucher appears valid, domain cert included")
                #print(voucher[ivv]["pinned-domain-cert"])
                dc = voucher[ivv]["pinned-domain-cert"]
                dc_bytes = b64d(dc)
                # save domain cert in PEM format
                with open(domain_cert_file, "w") as f:
                    f.write(ssl.DER_cert_to_PEM_cert(dc_bytes))
            if ok:
                # save voucher
                with open(voucher_file, "w") as f:
                    f.write(json.dumps(voucher))
                
                # This is where actions in Section 5.9 of RFC 8995 should go.
                # One example...
                res2 = try_get(base_url+"est/cacerts")
                if (not res2==None) and (res2.status_code == 200):
                    ca_certs = res2.content.decode("utf-8")
                    graspi.tprint("CA certs retrieved")
                    # save CA file in PEM format
                    with open(ca_file, "w") as f:
                        f.write(ca_certs)
                else:
                    fail("Failure on cacerts")
        else:
            e = res.content.decode("utf-8").split("Message: ")[1].split(".</p>")[0]
            fail("Request voucher error", res.status_code, e)
            if e == "Token claim failed":
                crash(e)

        if ok:

            # Test telemetry

            graspi.tprint("Testing telemetry")
            
            tel={
                "version": 1,
                "status":False,
                "reason":"Just a test",
                "reason-context": { "additional" : "JSON" }
            }
            res3 = try_post(base_url+"brski/voucher_status", tel)
            if res3==None:
                graspi.tprint("Failure on voucher status")
            else:
                graspi.tprint("Voucher Status reply:", res3.status_code)

            tel={
                "version": 1,
                "status":True,
                "reason":"Just another test",
                "reason-context": { "additional" : "JSON" }
            }
            res4 = try_post(base_url+"brski/enrollstatus", tel)
            if res4==None:
                graspi.tprint("Failure on enroll status")
            else:
                graspi.tprint("Enroll Status reply:", res4.status_code)  
            
        if ok:
            break  # all good
        else:
            # Failure, tag this proxy as expired.
            graspi.tprint("Registration failure, expiring that proxy")
            graspi.expire_flood(_asa_nonce, proxy)
            proxy = None  # we'll try all over again
    except Exception as e:
        # Some network error...
        graspi.tprint("Network error, expiring that proxy", str(e))
        graspi.expire_flood(_asa_nonce, proxy)
        proxy = None  # we'll try all over again

graspi.tprint("Success: pledge will exit onboarding code")
time.sleep(20)


