#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""This is a proof of concept for CASA, a Corporate Authorized Signing Authority,
described in draft-carpenter-anima-otp-casa. It also includes a simplified
BRSKI registrar, based on RFC8995, RFC8366 and RFC7030.
"""

# Released under the BSD "Revised" License.
#                                                     
# Copyright (C) 2026 Brian E. Carpenter.                  
# All rights reserved.
#
# Some fragments from https://github.com/abrox/simplest were originally
# licensed under the MIT license, Copyright (C) 2019 Jukka-Pekka Sarjanen.

# 20260903 First version
# 20260911 CASA does not need to be DULL

import os
import sys
import shutil
import socket
import secrets
import requests
from requests.utils import DEFAULT_CA_BUNDLE_PATH as pki_cafile
import time
import threading
import atexit
from tkinter import Tk
from tkinter.filedialog import askdirectory
from tkinter.messagebox import askyesno, showinfo
from http.server import HTTPServer as HTTPServer4
class HTTPServer(HTTPServer4):
    address_family = socket.AF_INET6
    protocol_version = "HTTP/1.1"
from http.server import BaseHTTPRequestHandler
import ssl
import base64
import json
from casa_setup import *
from casa_odevid import create_odevid
sys.path.insert(0, '..') # in case graspi.py is one level up
import graspi

printing = True   # Want output

asa_handle = None # global for GRASP operations

tokens = [] # array of all tokens
apdls  = [] # array of apdl IDs
flags  = [] # array of all flags

vault_lock = threading.Lock()
log_lock = threading.Lock()

allow_any_claim = False

# set up file names

fpath = env_path + "/casa"
token_file = fpath + "/casa_tokens.bin"
flag_file = fpath + "/casa_flags.bin"
apdl_file = fpath + "/casa_apdls.bin"
fnlog = fpath + "/casa_log.txt"
est_cafile = fpath + "/cacert.pem"
est_certfile = fpath + "/casacert.pem"
est_keyfile = fpath + "/casakey.pem"



### acquire CASA's own certificate and key in binary:
### (not currently needed)
##cert_pem_bytes = open(est_certfile, "rb").read()
##key_pem_bytes  = open(est_keyfile, "rb").read()

# Useful functions...

def exit_handler(exctype, value, tb):
    log("CASA process exiting due to: "+ str({exctype.__name__}) + str({value}))
    sys.__excepthook__(exctype, value, tb)
    
def log(msg):
    """Add a message to the log file"""
    global fnlog, printing
    log_lock.acquire()
    open(fnlog, "a", encoding="utf-8").write(timestamp() + " " +msg + "\n")
    if printing:
        print(msg)
    log_lock.release()

def log_stats():
    log(str(flags.count(FREE))+" free tokens, " +
        str(flags.count(CLAIMED))+" claimed tokens, " +
        str(flags.count(CLAIMED_AS_APDL))+" APDLs issued.")

def write_vault():
    """Write back the vault"""
    global tokens, flags, apdls
    wf(token_file, tokens)
    wf(flag_file, flags)
    wf(apdl_file, apdls)
    log("Vault stored to disk")

def make_apdl():
    """Make a new APDL"""
    global tokens, flags, apdls
    newt = []
    newf = []
    vault_lock.acquire()
    # First create APDL's ID
    while True:
        apdl_id = secrets.token_bytes(token_l)
        if not apdl_id in tokens:
            break    # we have to check
    tokens.append(apdl_id)
    apdls.append(apdl_id) 
    flags.append(CLAIMED_AS_APDL)
    newt.append(apdl_id)         # First token in apdl is its own ID
    newf.append(CLAIMED_AS_APDL)
    for i in range(token_count):
        # Create a new token
        while True:
            new_token = secrets.token_bytes(token_l)
            if not new_token in tokens:
                break    # we have to check
        tokens.append(new_token)
        newt.append(new_token)
        flags.append(FREE)
        newf.append(FREE)
        apdls.append(apdl_id)
    write_vault()
    vault_lock.release()
    log("New APDL added to vault: " + apdl_id.hex())
    return(newt, newf)

def claim_token(token):
    """If token is available, mark it as claimed"""
    if allow_any_claim:
        return(True)
    global tokens, flags, apdls
    vault_lock.acquire()
    for i in range(len(tokens)):
        if token == tokens[i]:
            if flags[i] != FREE:
                vault_lock.release()
                log("Duplicate token claim")
                return(False)
            else:
                flags[i] = CLAIMED
                wf(flag_file, flags)
                write_vault()
                vault_lock.release()
                log("Token successfully claimed")
                return(True)   # all good
    vault_lock.release()
    log("Nonexistent token claim")
    return(False)

def manufacture_apdl():
    """Load a new APDL to external storage"""
    showinfo(title=T, message="Will create new APDL; insert formatted memory stick")
    root.update()
    stick = askdirectory(title="Select APDL destination directory")
    root.update()
    if askyesno(title=T, message="OK to overwrite?"):
        root.update()
        atokens, aflags = make_apdl()
        wf(stick+"/atokens.bin", atokens)
        wf(stick+"/aflags.bin", aflags)
##        shutil.copy(est_cafile, stick+"/cacert.pem")
        log("APDL written")
        showinfo(title=T, message="APDL written to storage")
        root.update()
    else:
        root.update()
        showinfo(title=T, message="No action taken")
        root.update()

class EstRequestHandler(BaseHTTPRequestHandler):

    """Callbacks and handlers for various EST URL's,
       per RFC7030.
       Adapted from https://github.com/abrox/simplest"""

    def log_message(self, format, *args):
        # This catches all server logs (including errors)
        log("EST Server " + format % args)

    def handle_error(self, request, client_address):
        # This catches internal connection or protocol exceptions
        log(f"Connection error from {client_address}")
        super().handle_error(request, client_address)        

    def do_GET(self):  # pylint: disable=C0103
        """"Implement essential EST HTTP GET messages."""

        path = self.path

        if path == '/.well-known/est/cacerts':
            self.handle_cacert()
        else:
            self.send_error(404, message = "No such request")

    def do_POST(self):  # pylint: disable=C0103
        """Implement EST HTTP POST requests.
           (Skip authentication.)
        """
        path = self.path

        if path == '/.well-known/est/simpleenroll':
            self.handle_simpleenroll()
        elif path == '/.well-known/est/simplereenroll':
            self.handle_simplerenroll()
        elif path == '/.well-known/brski/requestvoucher':
            self.handle_brski_req_voucher()
        elif path == '/.well-known/brski/voucher_status':
            self.handle_brski_voucher_status()
        elif path == '/.well-known/brski/enrollstatus':
            self.handle_brski_enrollstatus()
        else:
            self.send_error(404, message = "No such request")
            
######## GET and POST actions as in https://github.com/abrox/simplest follow:
            
    def handle_cacert(self):
        """Handle cacert request.
           Read cacert from disk,create and send response.
        """
        file = open(est_cafile, "r")
        ca_certs = file.read()
        file.close()
        self.set_est_rsp_header(len(ca_certs))
        self.wfile.write(ca_certs.encode('utf-8'))

    def handle_simpleenroll(self):
        """Handler for simpleenroll request.
           Read request, create certificate and response.
        """
        content_length = int(self.headers['Content-Length'])
        csr = self.rfile.read(content_length)
        cert = sign_certificate(csr)
        self.set_est_rsp_header(len(cert))
        self.wfile.write(cert.encode('utf-8'))

    def handle_simplerenroll(self):
        """Basically identical request-> handle with same handler."""
        self.handle_simpleenroll()

######## End of actions as in https://github.com/abrox/simplest

######## BRSKI POST actions simplified from RFC 8995 follow:

    def handle_brski_req_voucher(self):
        """RFC8995 section 5.2"""

        content_length = int(self.headers['Content-Length'])
        req = b64d(self.rfile.read(content_length)).decode("utf-8")
        log(self.path)
        #pledge_cert = self.request.getpeercert(binary_form=True) #ineffective
        req = verify_json(req, fpath)
        if not req:
            log("JSON malsigned")
            self.send_error(403, message="JSON malsigned")
            return
        
        if req[ivrv]["proximity-registrar-cert"] == end_cert:
            nonce = req[ivrv]["nonce"]
            serial = req[ivrv]["serial-number"]
            log("Claiming "+serial)     
            if claim_token(bytes.fromhex(serial)):
                # successful claim: save certificate and return voucher
                pledge_cert = req[ivrv]["pledge-self-cert"]
                # save pledge certificate in vault
                with open(fpath+"/"+serial+".pem", "wb") as f:
                    f.write(b64d(pledge_cert))
                # create and sign voucher
                vouch = {ivv:
                          {"nonce": nonce,
                           "serial-number": serial,
                           "assertion": "logged",
                           "pinned-domain-cert": end_cert 
                           }}
                signed_voucher = sign_json(vouch, est_certfile,est_keyfile, fpath)
                # send voucher to pledge
                response = b64e(signed_voucher) #.decode("utf-8")
                self.set_est_rsp_header(len(response))
                self.wfile.write(response)
            else:
                self.send_error(403, message="Token claim failed")
        else:
            log("End certificate mismatch")
            self.send_error(403, message="End certificate mismatch")
        
    def handle_brski_voucher_status(self):
        """RFC8995 section 5.7"""

        content_length = int(self.headers['Content-Length'])
        req = self.rfile.read(content_length).decode("utf-8")
        log(self.path)
        req = json.loads(req)
        if req["version"] == 1:
            log("Voucher status: "+str(req["status"]))
            if req["reason"]:
                log(req["reason"])
            response = b"OK"
            self.set_est_rsp_header(len(response))
            self.wfile.write(response)
        else:
            log("Unknown telemetry version")
            self.send_error(404, message="Unknown telemetry version")
        
    def handle_brski_enrollstatus(self):
        """RFC8995 section 5.9.4"""
        
        content_length = int(self.headers['Content-Length'])
        req = self.rfile.read(content_length).decode("utf-8")
        log(self.path)
        req = json.loads(req)
        if req["version"] == 1:
            log("Enrollment status: "+str(req["status"]))
            if req["reason"]:
                log(req["reason"])
            response = b"OK"
            self.set_est_rsp_header(len(response))
            self.wfile.write(response)
        else:
            log("Unknown telemetry version")
            self.send_error(404, message="Unknown telemetry version")

######## End of BRSKI POST actions

    def set_est_rsp_header(self, data_len):
        """ Utility to create rsp header for messages."""
        self.send_response(200)
        self.send_header('Content-type', 'application/pkcs7-mime')
        self.send_header('Content-Transfer-Encoding', 'base64')
        self.send_header('Content-Length', data_len)
        self.end_headers()
        

class EST_server(threading.Thread):
    """Thread to spin off EST server, i.e. the BRSKI registrar,
       per RFC7030 and RFC8995.
       Adapted from https://github.com/abrox/simplest"""

    def __init__(self):
        threading.Thread.__init__(self, daemon=True)
        
    def run(self):
        global asa_handle
        # initialise GRASP instance
        graspi.skip_dialogue(selfing=True, ###be_dull=True,
                             silent=True, figging=False)
        # register ASA
        err, asa_handle = graspi.register_asa("CASA registrar")
        if err:
            log("GRASP ASA registration error: "+graspi.etext[err])
            raise RuntimeError("EST server early exit")
        grasp_address = graspi.grasp._my_address # address determined by GRASP
        est_server_address = str(grasp_address)
        log("Registrar starting on "+est_server_address+" port "+str(est_port))
        ##modes = [ssl.CERT_NONE, ssl.CERT_OPTIONAL, ssl.CERT_REQUIRED]
        purpose = ssl.Purpose.CLIENT_AUTH
        context = ssl.create_default_context(purpose)   #,cafile=est_cafile) breaks everything
        context.verify_mode = ssl.CERT_OPTIONAL         # CERT_NONE to suppress verification
        context.load_cert_chain(est_certfile, keyfile = est_keyfile)
        httpd = HTTPServer((est_server_address, est_port), EstRequestHandler)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        # Start GRASP registrar announcement
        flooder(asa_handle, grasp_address).start()
        #Start EST server itself
        httpd.serve_forever()  # will never return
        # if we ever get here, we'd like to hear about it
        log("EST server unexpected exit")
        raise RuntimeError("EST server unexpected exit")

class flooder(threading.Thread):
    """Thread to flood GRASP objective repeatedly"""
    def __init__(self, asa_handle, server_address):
        threading.Thread.__init__(self)
        self.asa_handle = asa_handle
        self.server_address = server_address

    def run(self):

        # construct GRASP locator and objective
        
        locator = graspi.asa_locator(self.server_address, None, False)
        locator.protocol = socket.IPPROTO_TCP
        locator.port = est_port
        locator.is_ipaddress = True

        grasp_obj = graspi.objective("AN_join_registrar")
        grasp_obj.loop_count = radius
        grasp_obj.synch = True
        grasp_obj.value = "EST-TLS"

        # register objective

        err = graspi.register_obj(asa_handle, grasp_obj)
        if err:
            log("GRASP Objective registration error: "+graspi.etext[err])
            return(False)
    
        log("GRASP flood starting in 15s") # delay to ensure EST server starts
        time.sleep(15)
        while True:
            graspi.flood(self.asa_handle, 120000,
                        graspi.tagged_objective(grasp_obj, locator))
            time.sleep(60)


            
###################################
# Start of main code
###################################

# Check if vault exists

if not os.path.exists(fpath):
    # This should happen exactly once in the life of a CASA host

    # Create directory for CASA vault
    os.mkdir(fpath)
    
    # Create CASA's key pair (using ODevID format for convenience)
    create_odevid("CASA "+timestamp(), est_keyfile, est_certfile)

# Check if key pair has been installed
if not (os.path.exists(est_certfile) and os.path.exists(est_keyfile)):
    print("Missing PEM file(s)")
    time.sleep(10)
    exit(0)

# get certfile string for later checks

with open(est_certfile, "r", encoding="utf-8") as file:
    end_cert = file.read()    
end_cert = stripcert(end_cert)
          

# Initialise GUI for user interaction

root = Tk()
root.withdraw()  # we don't want a full GUI    
T = "CASA"
printing = askyesno(title=T, message="Print log?")
allow_any_claim = askyesno(title=T,
                           message="Test mode allowing duplicate claims?")

# Open log file & register exit handler

log("CASA start " + timestamp())
sys.excepthook = exit_handler

if not os.path.exists(token_file):
    # This should happen exactly once in the life of a CASA
    open(token_file, 'w').close()  # create empty files (but leave log file alone)
    open(flag_file, 'w').close()
    open(apdl_file, 'w').close()
    log("New CASA - created vault")
    
    # each item in the token file will be token_l random bytes
    # each item in the flag will be one byte (initially zero)
    # each item in the apdl file will be the assigned apdl ID
    
else:
    #CASA has restarted, refresh data from vault
    
    tokens = rf(token_file, token_l)
    flags = rf(flag_file, 1)
    apdls = rf(apdl_file, token_l)
   
    log("Downloaded vault")
    log_stats()

# Make local copy of site CA file

shutil.copy(pki_cafile, est_cafile)


# From now on there will be multiple threads so the vault
# must be protected using vault_lock.

EST_server().start()

while True:
    log("CASA is ready to issue APDLs")
##    Residual fragments from testing
##    tt=tokens[123]
##    print(claim_token(tt))
##    print(claim_token(tt))
##    print(claim_token(secrets.token_bytes(token_l)))
##    t,f = make_apdl()
##    print("APDL sizes",len(t),len(f))

    if askyesno(title=T, message="Need a new APDL today?"):
        root.update()
        manufacture_apdl()
    else:
        root.update()
    time.sleep(300) # ask again in 5 minutes
    log_stats()
