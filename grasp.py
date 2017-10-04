"""########################################################
########################################################
#                                                     
# Generic Autonomic Signaling Protocol (GRASP)        
#                                                     
# GRASP engine and API                                
#                                                     
# Module name is 'grasp'
#                                                     
# This is a prototype/demo implementation of GRASP in 
# Python 3.4, based on draft-ietf-anima-grasp-15.txt
# It is not guaranteed or validated in any way and is 
# both incomplete and probably wrong. It makes no claim
# to be production-quality code. Its main purpose is to
# help improve the protocol specification.            
#                                                     
# Because it's demonstration code written in an       
# interpreted language, performance is slow.          
#                                                     
# SECURITY WARNINGS:                                  
#  - assumes ACP up on all interfaces (or none)       
#  - doesn't even try wrapping TCP in TLS             
#  - does not watch for interface up/down changes     
#                                                     
# LIMITATIONS:                                        
#  - only coded for IPv6, any IPv4 is accidental
#  - survival of address changes and CPU sleep/wakeup is patchy
#  - FQDN and URI locators incompletely supported          
#  - no code for rapid mode                           
#  - relay code is lazy (no rate control)                            
#  - all unicast transactions use TCP (no unicast UDP)
#  - the spec allows an optional Objective option in     
#      Response messages: not implemented             
#  - workarounds for defects in Python socket module  
#      and Windows socket peculiarities. More testing 
#      on BSD and Linux needed. Not tested on any Apple
#      device or on Android.
#
# Released under the BSD 2-Clause "Simplified" or "FreeBSD"
# License as follows:
#                                                     
# Copyright (C) 2015-2017 Brian E. Carpenter.                  
# All rights reserved.
#
# Redistribution and use in source and binary forms, with
# or without modification, are permitted provided that the
# following conditions are met:
#
# 1. Redistributions of source code must retain the above
# copyright notice, this list of conditions and the following
# disclaimer.
#
# 2. Redistributions in binary form must reproduce the above
# copyright notice, this list of conditions and the following
# disclaimer in the documentation and/or other materials
# provided with the distribution.                                  
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS  
# AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED 
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A     
# PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
# THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
# USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)    
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
# IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING   
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
# USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE        
# POSSIBILITY OF SUCH DAMAGE.                         
#                                                     
########################################################
########################################################"""

_version = "15-BC-20171004"

##########################################################
# The following change log records significant changes,
# not small bug fixes.

# Version 05 added proto/port to discovery responses

# 1. Update constants for revised CDDL
# 2. Add fields to discovered locator (class asa_locator) and objective
#    registry (class _registered_objective)
# 3. Add option code and fields in response messages
# 4. Update generation and parsing of response messages accordingly
# 5. Change from a global TCP listener to a per-objective TCP listener
# 6. Change register_objective to obtain a TCP port and socket and
#    launch its own listener
# 7. Make this listener exit if the objective is deregistered (but only
#    if new requests come in, otherwise it sleeps harmlessly for ever)

# 20160601 Added discovery cache timeout, and detection of address changes

# 20160605 Added partial recovery after system sleep

# 20160619 Fixed to allow reentrant calls to listen_neg (and listen_syn)

# Version 06 added no protocol changes

# Version 07 added ttl & locator to flood cache entries, and ttl to discovery response

# 20161003 added bubble output option with tkinter

# Version 08 added partial support of M_INVALID

# Version 09 added the F_NEG_DRY flag, modified M_FLOOD format

# 20170122 added Flag24 handling to API

# 20170124 changed error returns to integers (incompatible change to API)

# 20170221 changed session nonce to store packed locator insted of IPv6Address

# 20170224 improved flag bit handling

# 20170429 port 7017 assigned

# 20170518 added interactive choice of test mode (instead of countdown)

# 20170528 fixed several bugs in discovery relaying

# Version 13 improved calculation of discovery timeouts

# 20170604 added initialisation deferral

# Version 15 should conform to RFC-to-be

# 20170721 multicast addresses ff02::13 and 224.0.0.119 assigned

# 20170819 improved handling for long messages

# 20170824 added skip_dialogue() to API

# 20170929 added send_invalid() to API

# 20171003 added inbound message checking option, fixed bug in M_FLOOD format

##########################################################

####################################
#                                  #
# Python version check             #
#                                  #
####################################

import sys
if sys.version_info[0] < 3 or \
   (sys.version_info[0] == 3 and sys.version_info[1]) < 4:
    raise RuntimeError("Must use Python 3.4 or later")

# Each ASA starts with "import grasp"
# List of main classes and functions included in the API:

def init(self):
    __all__ = ['objective', 'asa_locator',
                   'register_asa', 'deregister_asa', 'register_obj',
                   'deregister_obj', 'discover',
                   'req_negotiate', 'negotiate_step', 'negotiate_wait',
                   'end_negotiate', 'listen_negotiate', 'stop_negotiate',
                   'synchronize', 'listen_synchronize', 'stop_synchronize',
                   'flood', 'get_flood', 'expire_flood']

####################################
#                                  #
# Imports                          #
#                                  #
####################################

import time
import os
import errno
import threading
import queue
import socket
import struct
import ipaddress
import ssl
import random
import binascii
import copy
### for bubbles
try:
    import tkinter as tk
    from tkinter import font
except:
    print("Could not import tkinter. No pretty printing.")
    time.sleep(10)
###
try:
    import cbor
except:
    print("Could not import cbor. Please do 'pip3 install cbor' and try again.")
    time.sleep(10)
    exit()
try:
    import acp
except:
    print("Could not import acp. Please copy acp.py to the current directory and try again.")
    time.sleep(10)
    exit()

#Work-around for missing constant in Python socket module on Windows.
#Isn't it just a stupid language feature that this is allowed???
if os.name=="nt":
    socket.IPPROTO_IPV6 = 41

####################################
#                                  #
# Data types and global data       #
#                                  #
####################################


####################################
# ASA registry                     #
####################################

class _asa_instance:
    """Internal use only"""
    def __init__(self, nonce, name):
        self.nonce = nonce    #the ASA's nonce
        self.name = name      #the ASA's name string

# _asa_registry - list of _asa_instance
# _asa_lock - lock for _asa_registry

####################################
# Objectives & registry            #
####################################

class objective:
    """
A GRASP objective:
 .name   String
 .neg    True if objective supports negotiation
 .dry    True if objective supportd dry-run negotiation
 .synch  True if objective supports synchronization
 .loop_count  Limit on negotiation steps etc.
 .value  A valid Python object
"""
    def __init__(self, name):
        self.name = name  #Unique name, string
        self.neg = False  #Set True if objective supports negotiation
        self.dry = False  #Set True if objective also supports dry-run negotiation
        self.synch = False  #Set True if objective supports synch
        self.loop_count = GRASP_DEF_LOOPCT #Default starting value
        self.value = 0    #Place holder; format undefined

def _oclone(obj):
    """Internal use only"""
###################################################
# Clones an objective for local use
# If you don't use this, you may unintenionally
# modify the caller's objective
# Just do obj=_oclone(obj)
###################################################
    cobj=objective(obj.name)
    cobj.neg=obj.neg
    cobj.dry=obj.dry
    cobj.synch=obj.synch
    cobj.loop_count=obj.loop_count
    cobj.value=obj.value
    return cobj        

class _registered_objective:
    """Internal use only"""
    def __init__(self, objective, asa_nonce):
        self.objective = objective
        self.asa_id    = asa_nonce
        self.protocol = socket.IPPROTO_TCP #default
        self.port = None
        self.discoverable = False # not discoverable until first listening
        self.local = False # link-local only if True
        self.ttl = _discCacheDefTimeOut # discovery cache timeout in milliseconds
        self.listening = 0 # counts active listeners
        self.listen_q = None

# _obj_registry - list of _registered_objective
# _obj_lock - lock for _obj_registry



####################################
# Discovery cache                  #
####################################

class _discovered_objective:
    """Internal use only"""
    def __init__(self, objective, asa_locators): 
        self.objective = objective      
        self.asa_locators  = asa_locators
                                  #asa_locators is a list of asa_locator

class asa_locator:
    """
Locator for a discovered peer ASA, also used for flooded objectives.
Values:
 .locator  The actual locator
 .protocol Transport protocol number
 .port     Port number
 .ifi      Interface identifier via which this was discovered
 .expire   int(time.monotonic()) value when this entry expires (0=never)
Booleans:
 .diverted  
 .is_ipaddress
 .is_fqdn
 .is_uri
"""
    def __init__(self, locator, ifi, diverted):

        self.locator = locator
        self.ifi = ifi   # Remember which interface this came from
        self.diverted = diverted  # True iff it was in a Divert option

        #Defaults
        self.protocol = socket.IPPROTO_TCP
        self.port = GRASP_LISTEN_PORT
        self.expire = 0
        
        #One of the following must be set when the object is created
        #Addresses to be stored in Python ipaddress class
        self.is_ipaddress = False
        self.is_fqdn = False
        self.is_uri = False
        
# _discovery_cache - list of _discovered_objective
# _disc_lock - lock for _discovery_cache



####################################
# Session ID cache                 #
####################################

class _session_instance:
    """Internal use only"""
    def __init__(self, id_value, id_active, id_source):
        self.id_value = id_value   #Integer 
        self.id_active = id_active #True if active 
        self.id_source = id_source #Source locator of ID if needed (packed)
        self.id_dq = None          #Queue if discovering    
        self.id_sock = None        #Socket if negotiating
        self.id_relayed = False    #True if has been relayed

class _session_nonce:
    """Internal use only"""
    def __init__(self, id_value, id_source):
        self.id_value = id_value   #Integer 
        self.id_source = id_source #Source locator of ID if non-local (packed)

# _session_id_cache - list of _session_instance
# _sess_lock - lock for _session_id_cache

# Session_ID cache contains
#  - all currently active Session_IDs
#  - foreign source address if any
#  - status for each one (in use or inactive)
#  - as memory permits, all previously seen Session_IDs (status inactive) to avoid reuse

####################################
# Flood cache                      #
####################################

class tagged_objective:
    """An objective tagged with its source asa_locator"""
    def __init__(self, objective, source):
        self.objective = objective
        self.source    = source # an asa_locator (including expiry time)

# _flood_cache  - list of tagged_objective
# _flood_lock - lock for _flood_cache

# Flood cache contains flooded objectives with their values and tagged
# with their source address

####################################
# Other global variables           #
#                                  #
# Reminder: any of these that get  #
# assigned inside any function or  #
# thread must be declared 'global' #
# inside that function             #
####################################

_grasp_initialised = False #true after GRASP core has been initialised
_skip_dialogue = False     #true if ASA calls grasp.skip_dialogue
# _tls_required       #true if no ACP
# _secure             #true if either ACP or TLS is working
# _rapid_supported    #true if rapid mode allowed
# _mcq                #FIFO for incoming multicasts
# _drq                #FIFO for pending discovery responses
# _my_address         #this node's preferred global address
# _my_link_local      #this node's preferred link local address
# _session_locator    #address used to disambiguate session ids (if initiator field used)
# _ll_zone_ids        #list of [IPv6 Zone (interface) index,LL address]
# _said_no_route      #flag used by watcher to limit printing
# _mcssocks           #list of multicast sending sockets
# _relay_needed       #True if multiple interfaces require Discovery/Flood relaying
# _mc_restart         #True if system wakeup detected - multicast listeners must restart
# _i_sent_it          #session ID of most recent discovery multicast, used in a hack
# test_mode           #True iff module is running in test mode
# listen_self         #True iff listening to own LL multicasts for testing
# test_divert         #True to force a divert message from discovery
# mess_check          #True to trigger strict message checking
# _make_invalid       #True to throw a test M_INVALID
# _make_badmess       #True to throw a malformed message
# _dobubbles          #True to enable bubble printing



####################################
# GRASP protocol constants         #
####################################

# Note: there is no reasonable way to define constants in Python.
# These objects could all be overwritten by programming errors.

M_NOOP = 0
M_DISCOVERY = 1
M_RESPONSE = 2
M_REQ_NEG = 3
M_REQ_SYN = 4
M_NEGOTIATE = 5
M_END = 6
M_WAIT = 7
M_SYNCH = 8
M_FLOOD = 9
M_INVALID = 99

O_DIVERT = 100
O_ACCEPT = 101
O_DECLINE = 102
O_IPv6_LOCATOR = 103
O_IPv4_LOCATOR = 104
O_FQDN_LOCATOR = 105
O_URI_LOCATOR = 106

F_DISC = 0    # valid for discovery
F_NEG = 1     # valid for negotiation
F_SYNCH = 2   # valid for synchronization
F_NEG_DRY = 3 # negotiation is dry-run


ALL_GRASP_NEIGHBORS_6 = ipaddress.IPv6Address('ff02::13')   # LL multicast
ALL_GRASP_NEIGHBORS_4 = ipaddress.IPv4Address('224.0.0.119') # LL multicast
GRASP_LISTEN_PORT = 7017 # IANA port number
GRASP_DEF_TIMEOUT = 60000 # milliseconds
GRASP_DEF_LOOPCT = 6
GRASP_DEF_MAX_SIZE = 2048 # max message size

unspec_address = ipaddress.IPv6Address('::') # Used in special cases to indicate link local address

####################################
# Support for flag bits            #
####################################

def bit(b):
    """Internal use only"""
    # return bit b on
    return 2**b

B_DISC = bit(F_DISC)
B_NEG =  bit(F_NEG)
B_SYNCH = bit(F_SYNCH)
B_DRY = bit(F_NEG_DRY)

def _flagword(obj):
    """Internal use only"""
    #create the flags word for an objective
    _f = B_DISC #everything's discoverable
    if obj.neg:
        _f |= B_NEG
    if obj.synch:
        _f |= B_SYNCH
    if obj.dry:
        _f |= B_DRY
    return _f

def _flags(flagword):
    """Internal use only"""
    #return Boolean flags for an objective
    return bool(flagword&B_NEG), bool(flagword&B_SYNCH), \
           bool(flagword&B_DRY)

  
##F_DISC_bits = bit(F_DISC)
##F_NEG_bits = F_DISC_bits|bit(F_NEG)
##F_SYNCH_bits = F_DISC_bits|bit(F_SYNCH)
##F_NEG_DRY_bits = F_NEG_bits|bit(F_NEG_DRY)


####################################
# GRASP engine internal constants  #
####################################

_asaRegistryLimit = 100
_sessionCacheLimit = _asaRegistryLimit + 1000
_objRegistryLimit = 200
_discCacheLimit = 500
_discCacheDefTimeOut = 10*GRASP_DEF_TIMEOUT  # milliseconds
_floodCacheLimit = 100
_discQlimit = 10
_listenQlimit = 5
_multQlimit = 100
_minRelayGap = 500      # milliseconds (unused, intended for relay throttling)
_discTimeoutUnit = 100  # milliseconds (discovery timeout per hop)

####################################
# List offsets for raw message     #
# contents (for poor man's parsing)#
####################################

_Op_Opt = 0 #option code in an option
_Op_Con = 1 #first specific item in an option
_Op_Proto = 2 #protocol number in a locator option
_Op_Port = 3  #port number in a locator option

_Pl_Msg = 0 #message type in a message payload
_Pl_Ses = 1 #session ID in a message payload
_Pl_Ini = 2 #initiator in a message payload
_Pl_Con = 2 #first specific item in a normal message payload
_Pl_TTL  = _Pl_Ini+1  #TTL in response or flood payload
_Pl_Aloc = _Pl_TTL+1  #locator option in response payload
_Pl_FCon = _Pl_TTL+1  #list of [locator,objective] in flood payload
_Pl_Dobj = _Pl_Ini+1  #objective in discovery payload

_Ob_Nam = 0 #name in an objective
_Ob_Flg = 1 #flags in an objective
_Ob_LCt = 2 #loop count in an objective
_Ob_Val = 3 #value object in an objective

####################################
# Error codes and English-language #
# error texts                      #
####################################

class _error_codes:
    """names for the error codes"""
    def __init__(self):
        self.ok = 0
        self.declined = 1 #"Declined"
        self.noReply = 2 #"No reply"
        self.unspec = 3 #"Unspecified error"
        self.ASAfull = 4 #"ASA registry full"
        self.dupASA = 5 #"Duplicate ASA name"
        self.noASA = 6 #"ASA not registered"
        self.notYourASA = 7 #"ASA registered but not by you"
        self.notBoth = 8 #"Objective cannot support both negotiation and synchronization"
        self.notDry = 9 #"Dry-run allowed only with negotiation"
        self.notOverlap = 10 #"Overlap not supported by this implementation"
        self.objFull = 11 #"Objective registry full"
        self.objReg = 12 #"Objective already registered"
        self.notYourObj = 13 #"Objective not registered by this ASA"
        self.notObj = 14 #"Objective not found"
        self.notNeg = 15 #"Objective not negotiable"
        self.noSecurity = 16 #"No security"
        self.noDiscReply = 17 #"No reply to discovery"
        self.sockErrNegRq = 18 #"Socket error sending negotiation request"
        self.noSession = 19 #"No session"
        self.noSocket = 20 #"No socket"
        self.loopExhausted = 21 #"Loop count exhausted"
        self.sockErrNegStep = 22 #"Socket error sending negotiation step"
        self.noPeer = 23 #"Negotiation peer not listening"
        self.CBORfail = 24 #"CBOR decode failure"
        self.invalidNeg = 25 #"Invalid Negotiate message"
        self.invalidEnd = 26 #"Invalid end message"
        self.noNegReply = 27 #"No reply to negotiation step"
        self.noValidStep = 28 #"No valid reply to negotiation step"
        self.sockErrWait = 29 #"Socket error sending wait message"
        self.sockErrEnd = 30 #"Socket error sending end message"
        self.IDclash = 31 #"Incoming request Session ID clash"
        self.notSynch = 32 #"Not a synchronization objective"
        self.notFloodDisc = 33 #"Not flooded and no reply to discovery"
        self.sockErrSynRq = 34 #"Socket error sending synch request"
        self.noListener = 35 #"Synchronization peer not listening"
        self.noSynchReply = 36 #"No reply to synchronization request"
        self.noValidSynch = 37 #"No valid reply to synchronization request"
        self.invalidLoc = 38 #"Invalid locator"
errors = _error_codes()

etext = ["OK",
        "Declined",
        "No reply",
        "Unspecified error",
        "ASA registry full",
        "Duplicate ASA name",
        "ASA not registered",
        "ASA registered but not by you",
        "Objective cannot support both negotiation and synchronization",
        "Dry-run allowed only with negotiation",
        "Overlap not supported by this implementation",
        "Objective registry full",
        "Objective already registered",
        "Objective not registered by this ASA",
        "Objective not found",
        "Objective not negotiable",
        "No security",
        "No reply to discovery",
        "Socket error sending negotiation request",
        "No session",
        "No socket",
        "Loop count exhausted",
        "Socket error sending negotiation step",
        "Negotiation peer not listening",
        "CBOR decode failure",
        "Invalid Negotiate message",
        "Invalid end message",
        "No reply to negotiation step",
        "No valid reply to negotiation step",
        "Socket error sending wait message",
        "Socket error sending end message",
        "Incoming request Session ID clash",
        "Not a synchronization objective",
        "Not flooded and no reply to discovery",
        "Socket error sending synch request",
        "Synchronization peer not listening",
        "No reply to synchronization request",
        "No valid reply to synchronization request",
        "Invalid locator"
       ]

####################################
#                                  #
# Registration functions           #
#                                  #
####################################

####################################
#                                  
# Tell GRASP to skip initial dialogue
#                                  
####################################

def skip_dialogue(testing=False, selfing=False, checking=False):
    """
####################################################################
# skip_dialogue(testing=False, selfing=False, checking=False)
#                                  
# Tells GRASP to skip initial dialogue
#
# Default is not test mode and not listening to own multicasts
# and not fully checking message syntax
# Must be called before register_asa()
#
# No return value                                  
####################################################################
"""
    global _skip_dialogue, test_mode, listen_self, mess_check, _grasp_initialised
    if _grasp_initialised:
        return
    _skip_dialogue = True
    test_mode = testing
    listen_self = selfing
    mess_check = checking


def register_asa(asa_name):
    """
####################################################################
# register_asa(asa_name)
#
# Tells the GRASP engine that a new ASA is starting up.
# Also triggers GRASP initialisation if needed.
# 
# return zero, asa_nonce  if successful
# return errorcode, None if failure
#
# Note - the ASA must store the asa_nonce (an opaque Python object)
# and use it in every subsequent GRASP call.
####################################################################
"""

    if not _grasp_initialised:
        _initialise_grasp()
        
    _asa_lock.acquire()
    if len(_asa_registry) >= _asaRegistryLimit:
        # no free space, fail
        _asa_lock.release()
        return errors.ASAfull, None
    elif ([clash for clash in _asa_registry if clash.name == asa_name]):
        # duplicate, fail
        _asa_lock.release()
        return errors.dupASA, None
    else:
        #append new one
        asa_nonce = _new_session(None)
        new_asa = _asa_instance(asa_nonce, asa_name)
        _asa_registry.append(new_asa)
        _asa_lock.release()
        return errors.ok, asa_nonce



def deregister_asa(asa_nonce, asa_name):
    """
####################################################################
# deregister_asa(asa_nonce, asa_name)
#
# Tells the GRASP engine that an ASA is going away.
# Deregisters its objectives too.
# We need this to happen automatically when an ASA crashes.
# 
# return zero if successful
# return errorcode if failure
####################################################################
"""
    # Stop all operations for this ASA (if registered with same PID)
    # and remove all relevant data.
    # (Need this to happen automatically if ASA exits)

    i = _retrieve_asa(asa_name)
    if i == -1:
        return errors.noASA
    elif (_asa_registry[i].nonce != asa_nonce):
        _asa_lock.release()
        return errors.notYourASA
    else:
        # Stops all operations for this ASA
        # by removing all registered objectives
        # and the ASA itself from their registries.
        # We have to keep the ASA lock for the whole time!

        _obj_lock.acquire()
        # The following loop looks unPythonesque, because
        # it shortens the list that it's looping over, so
        # it has to be done the old-fashioned way.
        j=0
        while j < len(_obj_registry):
            x = _obj_registry[j]
            if x.asa_id == asa_nonce:
                #found a match - delete it, which shortens the list
                del _obj_registry[j]
            else:
                j += 1
        _obj_lock.release()
        
        del _asa_registry[i]
        #mark the nonce as inactive
        _update_session(_session_instance(asa_nonce,False,None))
        _asa_lock.release()
        return errors.ok



def register_obj(asa_nonce, obj, ttl=None, discoverable=False, overlap=False, local=False):
    """
####################################################################
# register_obj(asa_nonce, objective,ttl=None
#              discoverable=False, overlap=False, local=False)
#
# Store an objective that this ASA supports and may modify.
#
# The objective becomes available for discovery only after
# a call to listen_negotiate() or listen_synchronize()
# unless the optional parameter discoverable is True.
#
# ttl is discovery time to live in milliseconds; the default
# is the GRASP default timeout.
#
# if discoverable==True, the objective is *immediately* discoverable
# even if the ASA is not listening.
#
# if overlap==True, more than one ASA may register this objective.
# (NOT supported in this implementation.)
#
# if local==True, discovery must return a link-local address
#
# The ASA may negotiate the objective or send synch or flood data.
# (Not needed if the ASA only wants to receive synch or flood data.)
# May be repeated for multiple objectives.
#
# return zero if successful
# return errorcode if failure
####################################################################
"""
    
    if _no_nonce(asa_nonce):
        return errors.noASA
    if (obj.neg and obj.synch) or (obj.dry and obj.synch):
        return errors.notBoth
    if (not obj.neg) and obj.dry:
        return errors.notDry
    if overlap:
        return errors.notOverlap
        

    #Clone the objective to avoid unintended side effects:
    #the copy in the registry will be distinct from the instance
    #supplied by the ASA
    obj=_oclone(obj)

    #Search the registry to detect any duplicate
    _obj_lock.acquire()
    if len(_obj_registry) >= _objRegistryLimit:
        # no free space, fail
        _obj_lock.release()
        return errors.objFull
    elif ([clash for clash in _obj_registry if clash.objective.name == obj.name]):
        # duplicate, fail
        _obj_lock.release()
        return errors.objReg        
    else:
        #start a listener thread if needed
        if obj.neg or obj.synch or obj.dry:
            listen_sock=socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listen_sock.bind(('',0))
            listen_port = listen_sock.getsockname()[1]
            _tcp_listen(listen_sock).start()
        else:
            listen_port = 0
        #append new one
        new_obj = _registered_objective(obj, asa_nonce)
        new_obj.port = listen_port
        new_obj.discoverable = discoverable # whether it can be discovered immediately
        new_obj.local = local # whether it must be assigned a link-local address
        if type(ttl).__name__ == "int" and ttl>0:
            new_obj.ttl = ttl
        _obj_registry.append(new_obj)
        _obj_lock.release()
        return errors.ok
    


def deregister_obj(asa_nonce, obj):
    """
####################################################################
# deregister_obj(asa_nonce, objective)
#
# Stops all operations on this objective (if registered)
# by removing it from the registry.
#
# return zero if successful
# return errorcode if failure
####################################################################
"""

    if _no_nonce(asa_nonce):
        return errors.noASA
    _obj_lock.acquire()
    # Can't use a comprehension because we need the actual
    # list entry in order to delete it.
    for i in range(len(_obj_registry)):
        x =_obj_registry[i]
        if x.objective.name == obj.name:
            #found it
            if x.asa_id != asa_nonce:
                _obj_lock.release()
                return errors.notYourObj
            #now delete it
            del _obj_registry[i]            
            _obj_lock.release()
            return errors.ok
    _obj_lock.release()
    return errors.notObj

####################################
#                                  #
# Support function:                #
# Receive complete raw message     #
# from TCP socket.                 #
#                                  #
####################################

def _recvraw(sock):
    """Internal use only"""
    rawmsg, send_addr = sock.recvfrom(GRASP_DEF_MAX_SIZE)
    if len(rawmsg) > 1200: # close to minimum IPv6 MTU
        #need to check briefly for a second chunk
        ttprint("Raw chunk length",len(rawmsg),"; waiting for more")
        _to = sock.gettimeout()
        sock.settimeout(0.2)
        try:
            raw2, _ = sock.recvfrom(GRASP_DEF_MAX_SIZE)
            if len(raw2):
                rawmsg += raw2
        except:
            pass #timeout, assume there's nothing more
        sock.settimeout(_to)
        
    return rawmsg, send_addr

####################################
#                                  #
# Discovery functions              #
#                                  #
####################################



def discover(asa_nonce, obj, timeout, flush=False, relay_ifi=False, relay_snonce=None):
    """
############################################################## 
# discover(asa_nonce, objective, timeout)
#
# Call in separate thread if asynchronous operation required.
# timeout in milliseconds (None for default)
#
# If there are cached results, they are returned immediately.
# If not, results will be collected until the timeout occurs.
#
# Optional parameter flush=True will flush cached results first
#
# Other optional parameters are for GRASP internal use only
#
# return zero, list of asa_locator if successful
#    If no peers discovered, list is []
# return errorcode, [] if failure
# Exponential backoff RECOMMENDED before retry.
##############################################################
"""
    global _i_sent_it
    if not relay_ifi:
        errorcode = _check_asa_obj(asa_nonce, obj, False)
        if errorcode:
            #raise RuntimeError("grasp.discover:"+etext[errorcode])
            return errorcode, []

    _disc_lock.acquire()
    # Can't use a comprehension because we need the actual
    # list entry in order to delete it.
    for i in range(len(_discovery_cache)):
        x = _discovery_cache[i]
        if x.objective.name == obj.name:
            del(_discovery_cache[i])
            if flush:
                ttprint("Discover flushing",obj.name)
                break
            else:
                _discovery_cache.append(x)   #make it Most Recently Used
                if not test_divert:
                    # delete any expired locators
                    j = 0
                    while len(x.asa_locators) > j:
                        _ex = x.asa_locators[j].expire
                        ttprint("Discovery expiry data:",obj.name,_ex, int(time.monotonic()))
                        if _ex and (_ex < int(time.monotonic())):
                            ttprint("Deleting stale discovery",j)
                            del x.asa_locators[j]
                        else:
                            j += 1
                            
                    # is there anything to return?                
                    if len(x.asa_locators) > 0:
                        _disc_lock.release()
                        return errors.ok, x.asa_locators                            
    _disc_lock.release()

    # Not already discovered (or flushed), launch discovery session

    if not relay_ifi:
        disc_sess = _new_session(_session_locator)
        snonce=_session_nonce(disc_sess,_session_locator.packed)
        #hack to detect own replies when running two instances
        _i_sent_it = disc_sess
        _to = _discTimeoutUnit*obj.loop_count
        if not timeout:
            timeout = _to
        else:
            timeout = max(timeout, _to)            
    else:
        # We are relaying, so cache remote session
        # We trust the timeout set by the relay process
        # (Note that if session is already cached, _insert_session will do nothing)
        snonce = relay_snonce
        disc_sess = snonce.id_value
        news = _session_instance(snonce.id_value,True,snonce.id_source)
        news.id_relayed = True
        _insert_session(news)

        
    # Make a discovery queue for this session
    _drq = queue.Queue(_discQlimit) # Limit number of pending discovery responses

    # Hang the queue on the session id
    s=_get_session(snonce)
    if s:
        s.id_dq = _drq
        if not _update_session(s):
           raise RuntimeError("Session ID anomaly") 
    else:
        raise RuntimeError("Session ID missing")

    # Prepare the message
    if relay_ifi:
        _sloc = snonce.id_source
    else:
        _sloc = _session_locator.packed
    msg_bytes = _ass_message(M_DISCOVERY, disc_sess, _sloc, obj)
    
    # Send it on all interfaces (except the source when relaying)
       
    # Can't use a comprehension because we need the actual
    # list index in order select the correct socket.
    for i in range(len(_ll_zone_ids)):
        if _ll_zone_ids[i][0] != relay_ifi:
            ttprint("Sending discovery on interface", _ll_zone_ids[i][0])
            try:
                _mcssocks[i][1].sendto(msg_bytes,0,(str(ALL_GRASP_NEIGHBORS_6), GRASP_LISTEN_PORT))  
            except:
                #might fail if CPU suspended etc
                tprint("MC socket failure in discover()")
                _fixmcsock(i)
                       
    # Note that listening threads for these sockets
    # were started during GRASP initialisation
    # _fixmcsock() has to fix them too
    
    # Until timeout, wait for and handle responses

    et = time.time() + timeout/1000
    
    while et > time.time():
        try:
            ttprint("Waiting for discovery response")
            tleft=et-time.time()
            #ttprint("Time left",tleft)
            if tleft > 0:
                dr = _drq.get(block=True, timeout=tleft)
            else:
                dr = _drq.get(block=False)
            payload = dr[2]
            ttprint("Got a discovery response",payload)
            #ttprint(payload[_Pl_Ses], disc_sess)
            if (payload[_Pl_Ses] == disc_sess) and (payload[_Pl_Ini] == _sloc):
                #it belongs here
                #strip it down to an option list and process it                
                _drloop(dr[1],payload[_Pl_TTL],payload[_Pl_Aloc:],obj,False)
            else:
                #response reached wrong queue
                tprint("Discovery response to wrong session")

        except queue.Empty:
            pass    #no valid response before timeout

    #when we get here the timeout has expired and anything
    #received is now in the discovery cache
    
    #extract results from discovery cache
    _disc_lock.acquire()
    for x in _discovery_cache:
        if x.objective.name == obj.name:
            answer = x.asa_locators
            _disc_lock.release()
            _disactivate_session(snonce)
            del _drq #garbage collect
            return errors.ok, answer
    _disc_lock.release()
        
    #no reply, return empty list
    _disactivate_session(snonce)
    ttprint("Returning empty discovery result")
    del _drq #garbage collect
    return errors.ok, []




def _drloop(ifi,ttl,payload,obj,inDivert):
    """Internal use only"""
##################################
# internal function for discover()
# input is an option list and
# the relevant objective.
# recurse when Divert found
##################################
    #payload is a list of GRASP options
    #how many options are present?
    ttprint("Entering drloop")
    nopts = len(payload)
    #ttprint("nopts", nopts)
    #ttprint("payload", payload)
    for i in range(nopts):
        opti = payload[i]
        if opti[_Op_Opt] == O_DIVERT:
            ttprint("drloop got a Divert option")
            #strip the option code and recurse
            _drloop(ifi,ttl,opti[_Op_Con:],obj,True)
            #ttprint("back from recursion")
        elif opti[_Op_Opt] == O_URI_LOCATOR:
            aloc = asa_locator(opti[_Op_Con],ifi,inDivert)
            aloc.is_uri = True
        else:
            if opti[_Op_Opt] == O_IPv4_LOCATOR or opti[_Op_Opt] == O_IPv6_LOCATOR:
                aloc = asa_locator(ipaddress.ip_address(opti[_Op_Con]), ifi, inDivert)
                aloc.is_ipaddress = True
            elif opti[_Op_Opt] == O_FQDN_LOCATOR:
                aloc = asa_locator(opti[_Op_Con],ifi,inDivert)
                aloc.is_fqdn = True
                
        #if we have something, complete the ASA locator
        #and add it to discovery cache entry for obj
        if 'aloc' in locals():
            aloc.protocol = opti[_Op_Proto]
            aloc.port = opti[_Op_Port]
            aloc.expire = int(time.monotonic() + ttl/1000)
            found = False
            _disc_lock.acquire()
            for x in _discovery_cache:
                if x.objective.name == obj.name:
                    ttprint("Adding locator to discovery cache")
                    x.asa_locators.append(aloc)
                    found = True
                    break
            if not found:
                ttprint("Adding objective to discovery cache")
                #add entry to discovery cache
                #but first, check length and garbage collect
                if len(_discovery_cache) >= _discCacheLimit:
                    del(_discovery_cache[0]) #delete Least Recently Used
                _discovery_cache.append(_discovered_objective(obj,[aloc]))
            _disc_lock.release()


####################################
#                                  #
# Negotiation functions            #
#                                  #
####################################



def req_negotiate(asa_nonce, obj, peer, timeout):
    """
##############################################################
# req_negotiate(asa_nonce, objective, peer, timeout)
#
# Request negotiation session with a peer ASA.
#
# asa_nonce identifies the calling ASA
#
# objective must include the requested value
#
# Note that the objective's loop_count value should be set to a
# suitable value by the ASA. If not, the GRASP default will apply.
#
# peer is the target node; it must be an asa_locator as returned by discover()
# If peer is None, discovery is performed first.
#
# timeout in milliseconds (None for default)
#
# Launch in a new thread if asynchronous operation required.
#
# return zero, session_nonce, objective
#
# The returned objective contains the first value proffered by the
# negotiation peer. Note that this instance of the objective
# MUST be used in the subsequent negotiation calls because
# it contains the loop count.
#
# The ASA MUST store the session_nonce (an opaque Python object)
# and use it in the subsequent negotiation calls
#
# return zero, None, objective - returns accepted value
# return errors.declined, None, string - other end declined, string gives reason
# return errorcode, None, None  - negotiation failed,
#                                 errorcode gives reason,
#                                 exponential backoff RECOMMENDED before retry.
##############################################################
"""

    # check that objective is registered and is owned by
    # the calling ASA
    errorcode = _check_asa_obj(asa_nonce, obj, False)
    if errorcode:
        return errorcode, None, None
    if not (obj.neg or obj.dry):
        return errors.notNeg, None, None
    # check that GRASP is running securely
    if not _secure:
        return errors.noSecurity, None, None

    if peer == None:
        #Caller did not supply locator, we can try discovery
        _, ll = discover(asa_nonce, obj, timeout)
        if len(ll)==0:
            return errors.noDiscReply, None, None
        else:
            #choose the first locator discovered
            peer = ll[0]
    
    #got a peer

    #build a Request message for the peer

    if not timeout:
        timeout = GRASP_DEF_TIMEOUT

    #create TCP socket, assemble message and send it
    #(lazy code, not checking that TCP is the right one to use)
    neg_sess = _new_session(None)
    snonce = _session_nonce(neg_sess,None)
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    if peer.locator.is_link_local:
        _ifi = peer.ifi
    else:
        _ifi = 0
    try:
        ttprint("Sending req_negotiate to",peer.locator, peer.port)
        sock.connect((str(peer.locator), peer.port,0,_ifi))
        msg_bytes = _ass_message(M_REQ_NEG, neg_sess, None, obj)
        sock.sendall(msg_bytes,0)
    except OSError as ex:
        tprint("Socket error sending negotiation request", ex)
        sock.close()
        _disactivate_session(snonce)
        return errors.sockErrNegRq, None, None
    
    # call common code to wait for reply and handle it
    return _negloop(snonce, obj, timeout, sock, True)
    
              




def negotiate_step(asa_nonce, snonce, obj, timeout):
    """
##############################################################
# negotiate_step(asa_nonce, session_nonce, objective, timeout)
#
# Continue negotiation session
#
# objective contains the next proffered value
# Note that this instance of the objective
# MUST be used in the subsequent negotiation calls because
# it contains the loop count.
#
# timeout in milliseconds (None for default)
#
# return: exactly like req_negotiate
##############################################################
"""
    global _make_invalid
    global _make_badmess
    
    # check that objective is registered and is owned by
    # the calling ASA
    errorcode = _check_asa_obj(asa_nonce, obj, False)
    if errorcode:
        return errorcode, None, None
    if not obj.neg:
        return errors.notNeg, None, None
    # check that GRASP is running securely
    if not _secure:
        return errors.noSecurity, None, None
    #verify session
    neg_sess = snonce.id_value
    s = _get_session(snonce)
    if not s:
        return errors.noSession, None, None
    #retrieve the socket
    sock = s.id_sock
    if sock == None:
        return errors.noSocket, None, None

    #loop count check
    #(loop count is decremented in _negloop)
    if obj.loop_count <1:
        #note that other end times out in this case
        return errors.loopExhausted, None, None

    if _make_invalid:  #this is a special hack for a test case only
        msg_bytes = _ass_message(M_INVALID, neg_sess, None, "Surprise!")
        sock.sendall(msg_bytes,0)
        _make_invalid = False
    
                                 
    #now send a negotiate message
    if _make_badmess: #this is a special hack for a test case only
        msg_bytes = _ass_message(M_NEGOTIATE, neg_sess, None, ["Rubbish"])
        _make_badmess = False
    else:
        msg_bytes = _ass_message(M_NEGOTIATE, neg_sess, None, obj)
    try:       
        sock.sendall(msg_bytes,0)
    except OSError as ex:
        ttprint("Socket error sending negotiation step", ex)
        sock.close()
        _disactivate_session(snonce)
        return errors.sockErrNegStep, None, None
    
    if not timeout:
        timeout = GRASP_DEF_TIMEOUT
    
    # call common code to wait for reply and handle it
    return _negloop(snonce, obj, timeout, sock, False)

    
 


def _negloop(snonce, obj, timeout, sock, new_request):
    """Internal use only"""
############################################
# internal function for req_negotiate()
# and negotiate_step()
#
# waits for a negotiation response and
# handles it
# 
# inputs are session nonce, user's objective,
# user's timeout, open socket, and a flag 
# set by req_negotiate
#
# return: exactly like req_negotiate
# 
############################################

    neg_sess = snonce.id_value
    loopAgain = True
    while loopAgain:
        loopAgain = False  #will loop only if we get a Wait message
        try:
            sock.settimeout(timeout/1000)
            rawmsg, send_addr = _recvraw(sock)
                    
            if len(rawmsg) == 0:
                sock.close()
                _disactivate_session(snonce)
                return errors.noPeer, None, None
                    
            ttprint("negloop: raw reply:", rawmsg)
            try:
                payload = cbor.loads(rawmsg)
            except:
                sock.close()
                _disactivate_session(snonce)
                return errors.CBORfail, None, None
            ttprint("negloop: CBOR->Python:", payload)
            if not _check_mess(payload):
                #invalid message, cannot process it
                tprint("Negotiate_step: invalid message format")
                sock.close()
                _disactivate_session(snonce)
                return errors.noValidStep, None, None
            if payload[_Pl_Ses]==neg_sess and new_request:
                # first operation for this socket - hang it onto session
                sess = _get_session(snonce)
                if not sess:
                    return errors.noSession, None, None
                sess.id_sock = sock
                _update_session(sess)
                
            if payload[_Pl_Msg]==M_INVALID:
                tprint("Got M_INVALID", payload[_Pl_Ses],payload[_Pl_Con])
            elif payload[_Pl_Msg]==M_NEGOTIATE and payload[_Pl_Ses]==neg_sess:
                ttprint("negloop: got NEGOTIATE")
                #payload[_Pl_Con] is the objective
                rec_obj = objective(payload[_Pl_Con][_Ob_Nam]) #the name
                _f = payload[_Pl_Con][_Ob_Flg]
                rec_obj.neg, rec_obj.synch, rec_obj.dry = _flags(_f)
                if rec_obj.dry:
                    ttprint("Received Dry")
                #decrement loop count
                rec_obj.loop_count = payload[_Pl_Con][_Ob_LCt]-1
                rec_obj.value = payload[_Pl_Con][_Ob_Val]
                rec_obj = _detag_obj(rec_obj)
                if (rec_obj.name == obj.name) and (rec_obj.neg == True):
                    return errors.ok, snonce, rec_obj #session and socket still open
                else:
                    sock.close()
                    _disactivate_session(snonce)
                    return errors.invalidNeg, None, None
                
            elif payload[_Pl_Msg]==M_WAIT and payload[_Pl_Ses]==neg_sess:
                ttprint("negloop: got WAIT")
                timeout = payload[_Pl_Con]
                loopAgain = True  #what we really want here is a GOTO
                
            elif payload[_Pl_Msg]==M_END and payload[_Pl_Ses]==neg_sess:
                ttprint("Negotiate_step: got END")
                # we're done
                sock.close()
                _disactivate_session(snonce)
                if payload[_Pl_Con][_Op_Opt] == O_ACCEPT:
                    return errors.ok, None, obj
                elif payload[_Pl_Con][_Op_Opt] == O_DECLINE:
                    if len(payload[_Pl_Con])>1:                     
                        return errors.declined, None, payload[_Pl_Con][_Op_Con] #copy error message
                    else:
                        return errors.declined, None, "" #no reason given
                else:
                    return errors.invalidEnd, None, None
            else:
                #if it isn't a valid message, ignore it
                ttprint("Negotiate_step: invalid negotiation response")     
        except OSError as ex:
            sock.close()
            _disactivate_session(snonce)
            ttprint("Socket error receiving negotiation response", ex)
            return errors.noNegReply, None, None
    #if all else fails...
    sock.close()
    _disactivate_session(snonce)
    return errors.noValidStep, None, None




def negotiate_wait(asa_nonce, snonce, timeout):
    """
##############################################################
# negotiate_wait(asa_nonce, session_nonce, timeout)
#
# Delay negotiation session
#
# timeout in milliseconds (None for default)
#
# return zero if successful
# return errorcode if failure
##############################################################
"""

    # check that the calling ASA is registered
    if _no_nonce(asa_nonce):
        return errors.noASA 
    # check that GRASP is running securely
    if not _secure:
        return errors.noSecurity
    #verify session
    s = _get_session(snonce)
    if not s:
        return errors.noSession
    #retrieve the socket
    sock = s.id_sock
    if sock == None:
        return errors.noSocket
    
    #now send a wait message
    if not timeout:
        timeout = GRASP_DEF_TIMEOUT
    msg_bytes = _ass_message(M_WAIT, s.id_value, None, timeout)
    try:
        sock.sendall(msg_bytes,0)
    except OSError as ex:
        ttprint("Socket error sending wait message", ex)
        sock.close()
        _disactivate_session(snonce)
        return errors.sockErrWait
    return errors.ok



def end_negotiate(asa_nonce, snonce, result, reason=None):
    """
##############################################################
# end_negotiate(asa_nonce, session_nonce, result, reason="why")
#
# End negotiation session
#
# result = True for accept, False for decline
# reason = optional string describing reason for decline
#
# return zero if successful
# return errorcode if failure
#
# Note that a redundant call to end_negotiate will get a
# reply such as (False, "No session") which does not need
# to be treated as an error.
##############################################################
"""
    # check that the calling ASA is registered
    if _no_nonce(asa_nonce):
        return errors.noASA 
    # check that GRASP is running securely
    if not _secure:
        return errors.noSecurity
    #verify session
    s = _get_session(snonce)
    if not s:
        return errors.noSession
    #retrieve the socket
    sock = s.id_sock
    if sock == None:
        return errors.noSocket
    
    #now send an end message, close the socket etc & return
    if result:
        end_opt = [O_ACCEPT]
    else:
        if reason == None:
            end_opt = [O_DECLINE]
        else:
            end_opt = [O_DECLINE, reason]
    msg_bytes = _ass_message(M_END, s.id_value, None, end_opt)
    try:
        sock.sendall(msg_bytes,0)
        sock.close()
        _disactivate_session(snonce)
    except OSError as ex:
        ttprint("Socket error sending end message", ex)
        sock.close()
        _disactivate_session(snonce)
        return errors.sockErrEnd
    return errors.ok


def send_invalid(asa_nonce, snonce, info="No information"):
    """
##############################################################
# send_invalid(asa_nonce, snonce, info="Diagnostic data")
#
# Send invalid message
#
# info = optional diagnostic data
#
# return zero if successful
# return errorcode if failure
#
# Ends the session abruptly.
# For use of this see M_INVALID in GRASP specification
##############################################################
"""
    # check that the calling ASA is registered
    if _no_nonce(asa_nonce):
        return errors.noASA 
    # check that GRASP is running securely
    if not _secure:
        return errors.noSecurity
    #verify session
    s = _get_session(snonce)
    if not s:
        return errors.noSession
    #retrieve the socket
    sock = s.id_sock
    if sock == None:
        return errors.noSocket
    
    #now send an invalid message, close the socket etc & return
    msg_bytes = _ass_message(M_INVALID, s.id_value, None, info)
    try:
        sock.sendall(msg_bytes,0)
        sock.close()
        _disactivate_session(snonce)
    except OSError as ex:
        ttprint("Socket error sending end message", ex)
        sock.close()
        _disactivate_session(snonce)
        return errors.sockErrEnd
    return errors.ok

 

def listen_negotiate(asa_nonce, obj):
    """
##############################################################
# listen_negotiate(asa_nonce, objective)
#
# Instructs GRASP to listen for negotiation
# requests for the given objective.
#
# Parameter is the objective of interest (no specific value needed)
#
# This function will block waiting for an incoming request.
# Call in a separate thread if asynchronous operation required.
#
# This call only returns after an incoming req_negotiate
# and must be followed by negotiate_step and/or negotiate_wait
# and/or end_negotiate
# listen_negotiate must then be repeated to restart listening.
#
# return zero, session_nonce, requested_objective
#
# The requested_objective contains the first value requested by the
# negotiation peer. Note that this instance of the objective
# MUST be used in the subsequent negotiation calls because
# it contains the loop count.
#
# The ASA MUST store the session_nonce (an opaque Python object)
# and use it in the subsequent negotiation calls.
#
# return errorcode, None, None     
##############################################################
"""

    # check that objective is registered and is owned by
    # the calling ASA
    errorcode = _check_asa_obj(asa_nonce, obj, False)
    if errorcode:
        return errorcode, None, None
    if not obj.neg:
        return errors.notNeg, None, None
    # check that GRASP is running securely
    if not _secure:
        return errors.noSecurity, None, None
    
    # set up the listening queue
    q = None
    _obj_lock.acquire()
    for x in _obj_registry:
        if x.objective.name == obj.name:
            if not x.listening:
                # set status in objective registry and start listener
                x.discoverable = True # as from now, discovery is possible
                x.listening += 1
                x.listen_q = queue.Queue(_listenQlimit)                
                q = x.listen_q  
                # note that there is no separate listener thread as for listen_synchronize
                break
            else:
                # already listening, this is a reentrant listen
                x.listening += 1
                q = x.listen_q
                break
    _obj_lock.release()
    
    # now we start to listen right here in the calling thread


    # get next request from queue
    # what we find in the queue is [asock,send_addr,payload]
    # payload is a Request Neg message
    # asock is a connected TCP socket

    # we block here until a request arrives
    ttprint("listen_negotiate: Waiting for a negotiate request")
    rq = q.get()
    ttprint("listen_negotiate: Got negotiate request from queue")

    #no longer listening until called again, so
    #decrement listening count in objective registry
    #and garbage-collect the queue
    _obj_lock.acquire()
    for x in _obj_registry:
        if x.objective.name == obj.name:
            x.listening -= 1
    _obj_lock.release()
    del q
    
    #build the session instance and nonce
    s_id = rq[2][_Pl_Ses]
    s_source = rq[1]
    s_nonce = _session_nonce(s_id,s_source.packed)
    #cache remote session along with socket
    news = _session_instance(s_id,True,s_source.packed)
    news.id_sock=rq[0]
    if _insert_session(news, _check_race = not test_mode):
        #(we bypass the race condition check iff in test mode)
        #return proffered objective to caller
        prof_obj = objective(rq[2][_Pl_Con][_Ob_Nam])
        _f = rq[2][_Pl_Con][_Ob_Flg]
        prof_obj.neg, prof_obj.synch, prof_obj.dry = _flags(_f)
        if prof_obj.dry:
            ttprint("Received Dry Request")   
        prof_obj.loop_count = rq[2][_Pl_Con][_Ob_LCt]
        prof_obj.value = rq[2][_Pl_Con][_Ob_Val]
        return errors.ok, s_nonce, _detag_obj(prof_obj)  # Negotiation starting
    else:
        # race condition clash between s_id and an existing session
        # this should be incredibly rare unless both sides are
        # using very poor random number generators
        return errors.IDclash, None, None

def stop_negotiate(asa_nonce, obj):
    """
##############################################################
# stop_negotiate(asa_nonce, objective)
#
# Instructs GRASP to stop listening for negotiation
# requests for the given objective.
#
# return zero if successful
# return errorcode if failure
##############################################################
"""
    
    # check that objective is registered and is owned by
    # the calling ASA
    
    errorcode = _check_asa_obj(asa_nonce, obj, False)
    if errorcode:
        return errorcode

    #clear its listening status in objective registry
    _obj_lock.acquire()
    for x in _obj_registry:
        if x.objective.name == obj.name:
            x.listening = 0
    _obj_lock.release() 
    return errors.ok


####################################
#                                  #
# Synchronization functions        #
#                                  #
####################################



def synchronize(asa_nonce, obj, loc, timeout):
    """
##############################################################
# synchronize(asa_nonce, objective, locator, timeout)
#
# Request synchronized value of the given objective.
#
# locator is an asa_locator as returned by discover()
#
# timeout in milliseconds (None for default)
#
# If the locator is None and the objective was already flooded,
# the first flooded value in the cache is returned.
# 
# Otherwise, synchronization with a discovered ASA is performed.
# In that case, if the locator is None, discovery is performed first. 
#
# This call should be repeated whenever the value is needed.
# Call in a separate thread if asynchronous operation required.
#
# Since this is essentially a read operation, any ASA can do
# it. Therefore we check that the ASA is registered but the
# objective doesn't need to be registered by the calling ASA.
#
# return zero, synch_objective   returns objective with its synchronized value
#
# return errorcode, None    synchronization failed
#                           errorcode gives reason.
#                           Exponential backoff RECOMMENDED before retry.
##############################################################
"""

    if _no_nonce(asa_nonce):
        return errors.noASA, None
    if not obj.synch:
        return errors.notSynch, None

    #Has the objective been flooded?

    if loc == None:
        _flood_lock.acquire()
        for x in _flood_cache:
            if x.objective.name == obj.name and \
               (x.source.expire == 0 or x.source.expire > int(time.monotonic())):
                _result = x.objective
                _flood_lock.release()
                return errors.ok, _result #return first unexpired flooded value
                #(Note that expired floods are garbage collected when
                #new flood multicasts are received, not here.)
        _flood_lock.release()
        #not flooded, we need to ask...

    if not timeout:
        timeout = GRASP_DEF_TIMEOUT

    if loc == None:
        #Caller did not supply locator, we can try discovery
        _, ll = discover(asa_nonce, obj, timeout)
        if len(ll)==0:
            return errors.notFloodDisc, None
        else:
            #choose the first locator discovered
            loc = ll[0]

    #request synch from the given locator
    #create TCP socket, assemble message and send it
    #(lazy code, not checking that TCP is the right one to use)
    sync_sess = _new_session(None)
    snonce = _session_nonce(sync_sess, None)
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    if loc.locator.is_link_local:
        _ifi = loc.ifi
    else:
        _ifi = 0
    try:
        ttprint("Sending request_syn to",loc.locator,loc.port,_ifi)
        sock.connect((str(loc.locator), loc.port,0,_ifi))
        msg_bytes = _ass_message(M_REQ_SYN, sync_sess, None, obj)
        sock.sendall(msg_bytes,0)
    except OSError as ex:
        tprint("Socket error sending synch request", ex)
        sock.close()
        _disactivate_session(snonce)
        return errors.sockErrSynRq, None
    #now listen for reply
    try:
        sock.settimeout(timeout/1000)
        rawmsg, send_addr = _recvraw(sock)
        sock.close()
        if len(rawmsg) == 0:
            _disactivate_session(snonce)
            return errors.noListener, None
        ttprint("Synch: raw reply:", rawmsg)
        try:
            payload = cbor.loads(rawmsg)
        except:
            _disactivate_session(snonce)
            return errors.CBORfail, None
        if not _check_mess(payload):
            #invalid message, cannot process it
            _disactivate_session(snonce)
            return errors.noValidSynch, None
        ttprint("Synch: CBOR->Python:", payload)
        if payload[_Pl_Msg]==M_SYNCH and payload[_Pl_Ses]==sync_sess:
            #payload[_Pl_Con] is the objective
            rec_obj = objective(payload[_Pl_Con][_Ob_Nam]) #the name
            rec_obj.synch = True
            rec_obj.loop_count = payload[_Pl_Con][_Ob_LCt]-1
            rec_obj.value = payload[_Pl_Con][_Ob_Val]
            if rec_obj.name == obj.name:
                _disactivate_session(snonce)
                return errors.ok, _detag_obj(rec_obj) #we're done!
        else:
            #if it isn't a valid synch message, ignore it
            ttprint("Invalid synch response")     
    except OSError as ex:
        sock.close()
        _disactivate_session(snonce)
        tprint("Socket error receiving synch message", ex)
        return errors.noSynchReply, None
    #all else fails...
    _disactivate_session(snonce)
    return errors.noValidSynch, None               



def listen_synchronize(asa_nonce, obj):
    """
##############################################################
# listen_synchronize(asa_nonce, objective)
#
# Instructs GRASP to listen for synchronization
# requests for the given objective, and to
# respond with the objective value given in the call.
#
# This call should be repeated whenever the value changes.
#
# return zero if successful
# return errorcode if failure
##############################################################
"""

    #clone the objective to avoid unintended side effects    
    obj = _oclone(obj)
    # check that objective is registered and is owned by
    # the calling ASA
    errorcode = _check_asa_obj(asa_nonce, obj, True)
    if errorcode:
        return errorcode
    # check that GRASP is running securely
    if not _secure:
        return errors.noSecurity
    
    #ttprint("listen_synchronize: Obj value recvd:",obj.name,obj.value)
    _obj_lock.acquire()
    for x in _obj_registry:
        if x.objective.name == obj.name:
            # Set value in objective registry.
            # Note that this objective has not been transmitted
            # so the value does not need detagging.
            x.objective.value = obj.value
            #ttprint("listen_synchronize: Obj value set",i,obj.name,obj.value,_obj_registry[i].objective.value)
            if not x.listening:
                # set status in objective registry and start listener
                x.discoverable = True # as from now, discovery is possible
                x.listening = 1
                x.listen_q =  queue.Queue(_listenQlimit)
                _synch_listen(obj).start()
                break
    _obj_lock.release() 
    
    return errors.ok



class _synch_listen(threading.Thread):
    """Internal use only"""
####################################################
# Listener thread for synch requests               #
#                                                  #
# This thread is invoked by listen_synchronize     #
# and must not be activated otherwise.             #
####################################################
    def __init__(self, obj):
        threading.Thread.__init__(self)
        self.obj = obj
        
    def run(self):
        #ttprint("synch_listen Obj in:", self.obj.name,self.obj.value)
        keep_going = True
        while keep_going:
            not_found = True
            _obj_lock.acquire()
            for x in _obj_registry:
                if x.objective.name == self.obj.name:
                    # we found our objective
                    #ttprint("synch_listen registry value:", x.objective.value)
                    not_found = False
                    if not x.listening:
                        # can stop listening and exit thread
                        _obj_lock.release()
                        keep_going = False                        
                    else:
                        # we're still listening
                        q = x.listen_q
                        _obj_lock.release()
                        # get next request from queue
                        # what we find in the queue is [asock,send_addr,payload]
                        # payload is a Request Synch message
                        # asock is a connected TCP socket
                        rq = q.get()

                        ttprint("Got synch request from queue")
                        # get the latest value from the registry
                        # (could have changed while we waited for the request)

                        #Note - we use this apparently pointless extra variable
                        # 'ovalue' because when testing inside a single node, there
                        # might be cases where the 'obj' parameter is the exact same
                        # object as the entry in '_obj_registry'
                        ovalue = None
                        _obj_lock.acquire()
                        for y in _obj_registry:
                            if y.objective.name == self.obj.name:
                                #ttprint("Objectives", y.objective, self.obj)
                                ovalue = y.objective.value
                                #ttprint("synch_listen Obj value:", ovalue)
                        # Note - this is the value stored in the registry so
                        # does not need detagging
                        self.obj.value = ovalue
                        _obj_lock.release()                        
                        # send back reply
                        msg_bytes = _ass_message(M_SYNCH, rq[2][_Pl_Ses], None, self.obj)
                        try:
                            rq[0].sendall(msg_bytes,0)
                            ttprint("Sent Synch")
                        except OSError as ex:
                            ttprint("Synch socket failure",ex)
                        rq[0].close()
                        break
               
            # should never need to do this, but race conditions
            # could perhaps arise
            if not_found:
                _obj_lock.release()
                keep_going = False
        ttprint("Exit synch_listen thread")


def stop_synchronize(asa_nonce, obj):
    """
##############################################################
# stop_synchronize(asa_nonce, objective)
#
# Instructs GRASP to stop listening for synchronization
# requests for the given objective.
#
# return zero if successful
# return errorcode if failure
##############################################################
"""
    # check that objective is registered and is owned by
    # the calling ASA
    
    errorcode = _check_asa_obj(asa_nonce, obj, True)
    if errorcode:
        return errorcode

    #clear its listening status in objective registry
    _obj_lock.acquire()
    for x in _obj_registry:
        if x.objective.name == obj.name:
            x.listening = 0
    _obj_lock.release() 
    return errors.ok



def flood(asa_nonce, ttl, *tagged_obj):
    """
##############################################################
# flood(asa_nonce, ttl, *tagged_obj)                               
#
# Instructs GRASP to flood the given synchronization
# objective(s) and their value(s) to all GRASP nodes.
# Checks that the ASA registered each objective.
# This call may be repeated whenever the value changes.
#
# The objective(s) must be tagged with a locator
# which is either [] or a valid asa_locator
#
# If the first objective is tagged with the unspecified
# address, the entire flood is treated as link-local:
#
#  - the address in the locator is replaced by the
#    relevant link local address
#  - the loop count is forced to 1
#
# ttl is in milliseconds (0 = infinity)
#
# return zero if successful
# return errorcode if failure
##############################################################
"""
   
    for x in tagged_obj:
        errorcode = _check_asa_obj(asa_nonce, x.objective, True)
        if errorcode:
            return errorcode   

    if tagged_obj[0].source and (tagged_obj[0].source.locator == unspec_address):
        tagged_obj[0].objective.loop_count = 1 # force link-local loop count
        _local_flood = True
    else:
        _local_flood = False

    _floodl = []
        
    for x in tagged_obj:
        if x.source == None:
            _l = [] # empty option
        elif x.source.locator == None:
            _l = [] # empty option            
        elif x.source.is_ipaddress:
            _l = [O_IPv6_LOCATOR, x.source.locator.packed, x.source.protocol, x.source.port]
        else:
            return errors.invalidLoc # Lazy, not allowing other formats
        _floodl.append([x.objective, _l])
        #ttprint("Flood list:",_floodl)
        
    flood_session = _new_session(_session_locator)
 
    #ttprint("Flood TTL:",ttl)

    if not ttl:
        ttl = 0 # Make it an integer rather than None or False
    
    # Can't use a comprehension because we need the actual
    # list index in order select the correct socket.
    for i in range(len(_ll_zone_ids)):
        if _l != []:
            if _l[1] == unspec_address.packed:
                _l[1] = _ll_zone_ids[i][1].packed # replace with LL address
        msg_bytes = _ass_message(M_FLOOD, flood_session, _session_locator.packed, ttl, _floodl)
        try:
            _mcssocks[i][1].sendto(msg_bytes,0,(str(ALL_GRASP_NEIGHBORS_6), GRASP_LISTEN_PORT))
        except:
            #might fail if CPU suspended etc
            ttprint("MC socket failure in flood()")
            _fixmcsock(i)
    _disactivate_session(_session_nonce(flood_session, None))
    return errors.ok

def get_flood(asa_nonce, obj):
    """
##############################################################
# get_flood(asa_nonce, objective)
#
# Request flooded values of the given objective.
#
# This call should be repeated whenever the value is needed.
#
# Since this is essentially a read operation, any ASA can do
# it. Therefore we check that the ASA is registered but the
# objective doesn't need to be registered by the calling ASA.
#
# return zero, tagged_objectives   returns a list of tagged_objective
#
# return errorcode, None    call failed
#                           errorcode gives reason.
#                           Exponential backoff RECOMMENDED before retry.
##############################################################
"""

    if _no_nonce(asa_nonce):
        return errors.noASA, None
    if not obj.synch:
        return errors.notSynch, None

    #Collect list of unexpired flooded tagged_objective
    #(Note that expired floods are garbage collected when
    #new flood multicasts are received, not here.)

    _l = []  #Initialise empty list
    
    _flood_lock.acquire()
    for x in _flood_cache:
        if x.objective.name == obj.name and \
           (x.source.expire == 0 or (x.source.expire > int(time.monotonic()))):
            _l.append(x)
    _flood_lock.release()

    return errors.ok, _l

def expire_flood(asa_nonce, tagged_obj):
    """
##############################################################
# expire_flood(asa_nonce, tagged_obj)
#
# Mark a flooded objective as expired
#
# This is a call that can only be used after a preceding
# call to get_flood() by an ASA that is capable of deciding
# that the flooded value is stale or invalid. To be used
# with care.
#
# tagged_obj   the tagged_objective to be expired
#
# return zero if successful
# return errorcode if failure
##############################################################
"""

    if _no_nonce(asa_nonce):
        return errors.noASA
    
    #(Note that expired floods are garbage collected when
    #new flood multicasts are received, not here.)
    _flood_lock.acquire()
    for x in _flood_cache:
        if (x == tagged_obj) and (x.source.expire > 0):
            x.source.expire = int(time.monotonic())-1
    _flood_lock.release()

    return errors.ok

####################################
#                                  #
# Internal functions               #
#                                  #
####################################

def hexit(xx):
    """Internal use only"""
    if type(xx).__name__ == "bytes":
        return binascii.b2a_hex(xx)
    elif type(xx).__name__ == "list":
        for i in range(len(xx)):
            xx[i] = hexit(xx[i])            
    return(xx)

##def gprint(*whatever, sep=' ', end='\n', file=sys.stdout, flush=False):
##    """To help with Python 2 downgrade, use exactly like print()"""
##    print(*whatever,sep=sep,end=end,file=file,flush=flush)


def tprint(*whatever,ttp=False):
    """Multi-thread printing, used exactly like print()"""

    #first get the module name
    a,b = str(threading.current_thread()).split('<')
    a,b = b.split('(')  
    _print_lock.acquire()
    #print module name and thread ID
    print(a,threading.get_ident(),end=" ",flush=False)
    _s=""
    #print whatever
    for x in whatever:
        try:
            if test_mode:           #want bytes printed in hex
                xx=copy.deepcopy(x) #avoid overwriting anything
                xx = hexit(xx)
            else:
                xx=x               
            _s=_s+str(xx)+" "
            print(xx,end=" ",flush=False)
        except:
            #in case UTF-8 string can't be printed
            print("[unprintable]",end="",flush=False)
    print("")

    if _dobubbles and not ttp:
        #Queue the text for bubble printing
        if len(_s) > 200:
            _s = _s[:200]+' ...' #truncate to fit
        try:
            bubbleQ.put(_s, block=False)
        except:
            pass   # Skip it if queue is full
    _print_lock.release()
    return


def ttprint(*whatever):
    """Multi-thread printing in test mode only, used exactly like print()"""

    if test_mode:
        tprint(*whatever,ttp=True)
    return

######################################
#
# Package to speak in bubbles
#
######################################

    
def init_bubble_text(cap):
    """
    Switch on bubble printing, which uses tkinter
    cap: a string that labels the bubble window.
    """

#------------
# Classes and functions

    class speakEasy:
        """Simple class to describe a message

        x, y: (int) anchor point for the message
        txt: (string) text of the message
        i: after drawing, canvas item for image
        j: after drawing, canvas item for text"""
        
        def __init__(self, x, y, txt):
            self.x = x     #coordinates
            self.y = y
            self.txt = txt #words

    def draw_bubble(can, bubble):
        """
        can : tkinter canvas
        bubble : a speakEasy object
        """
        global _bubblim, _myfont

        #print("Drawing x",bubble.x,"y",bubble.y,"text",bubble.txt)
        pos = (bubble.x, bubble.y)
        
        bubble.i=can.create_image((bubble.x, bubble.y), image=_bubblim)
        
        bubble.j=can.create_text((bubble.x-180,bubble.y-80), font=_myfont,
                             text=bubble.txt, anchor=tk.NW,width=_wrap_at)


    def raise_bubble(can, bubble):
        """
        can : tkinter canvas
        bubble : a speakEasy object
        """
        bubble.y -=step
        can.move(bubble.i,0,-step)
        can.move(bubble.j,0,-step)
        return

    class bubbler(threading.Thread):
        """Internal use only"""
        def __init__(self, cap):
            threading.Thread.__init__(self)
            self.cap = cap
            
        def run(self):

            global _dobubbles, _bubblim, _logoim, _myfont, _wrap_at, _bigstring, _bigstring2
            
            try:
                #make a window
                #Validate caption first
                _c=self.cap
                if _c == "":
                    _c=" GRASP" #default caption if blank
                elif _c[0] in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
                    _c = " "+_c #get round 'feature' in Tk
                root = tk.Tk(className=_c)
                
                #make images and a font
                _bubblim = tk.PhotoImage(data=_bigstring)
                _logoim = tk.PhotoImage(data=_bigstring2)
                del _bigstring
                del _bigstring2
                _myfont = font.Font(family='Arial',size=12,weight='bold')
                
                #set an icon
                root.tk.call('wm', 'iconphoto', root._w, _logoim)

                #window on top (doesn't work in all cases)
                root.lift()
         
                #size the window
                root.geometry(str(HEIGHT)+"x"+str(WIDTH))

                #make a canvas
                can = tk.Canvas(root)  
                can.config(background=backgroundCol) #colour it
                can.pack(fill=tk.BOTH, expand=1) #always full size        
                
                #draw blank canvas
                root.update_idletasks()
                root.update()
                bubbles = [] # empty message list
                _looping = True
                _pause = 0
            except:
                tprint("Could not start Tkinter")
                _looping = False

            while _looping:
                
                # Check print queue unless pausing
                if _pause <= 0:
                    try:
                        _tx = bubbleQ.get(block=False)
                    
                        #Build a bubble
                        _m=speakEasy(random.randrange(250,270),int(HEIGHT-70),_tx)

                        #Raise existing bubbles
                        for i in range(len(bubbles)):
                            if i==len(bubbles)-1:
                                #Extra raise for the most recent
                                raise_bubble(can,bubbles[i])
                            raise_bubble(can,bubbles[i])

                        #Draw the new one
                        draw_bubble(can,_m)
                        #Add new one to the display list
                        bubbles.append(_m)

                        #Delete the oldest one if off screen
                        if bubbles[0].y<-2*step:
                            can.delete(bubbles[0].i)
                            can.delete(bubbles[0].j)
                            del bubbles[0]
                        #tprint(len(bubbles),"bubbles now")

                        #Ask for a display pause
                        _pause = int(FRAMERATE/2)
                    except:
                        pass

                #Decrement pause
                if _pause > 0:
                    _pause -= 1
                
                #Update our display                
                if bubbles != []:
                    try:
                        root.update_idletasks()
                        root.update()
                    except:
                        _looping=False #Somebody closed the window

                # Wait before next loop
                time.sleep(1/FRAMERATE)

            #Exiting
            tprint("Bubbles over")
            _dobubbles = False
                
    #--------------
    # constants and global vars
    global _dobubbles, _bubblim, _myfont, _wrap_at
            
    WIDTH = 500
    HEIGHT = 500
    _wrap_at = 350 #width for text wrap
    step = 50 #how much to raise a bubble each time
    FRAMERATE = 10
    #make a random colour for the background
    r=random.randrange(1,255)
    g=random.randrange(1,255)
    b=random.randrange(1,255)
    backgroundCol="#{0:02x}{1:02x}{2:02x}".format(r,g,b)
    bubbles = []
    _bubblim = None
    _logoim = None
    _myfont = None
    _dobubbles = True
    #start a thread to do the work
    bubbler(cap).start()
    
    return


####################################
# ASA registry  functions          #
####################################

def _retrieve_asa(asa_name):
    """Internal use only"""
####################################
# Retrieve an ASA entry by name    #
#                                  #
# return index in registry         #
# RETURNS WITH _asa_lock ACQUIRED!  #
# return -1 if nonesuch            #
####################################
    _asa_lock.acquire()
    asa_ct = len(_asa_registry)
    for i in range(asa_ct):
        if asa_name == _asa_registry[i].name:
            return i
    _asa_lock.release()
    return -1



def _no_nonce(asa_nonce):
    """Internal use only"""
####################################
# Check a nonce                    #
#                                  #
# return True if nonce is absent   #
####################################
    # don't think we need the lock for this
    return not([x for x in _asa_registry if x.nonce == asa_nonce])



def _check_asa_obj(asa_nonce, obj, sending_synch):
    """Internal use only"""
####################################
# Check a calling ASA              #
#                                  #
# Return errorcode if              #
# - objective invalid              #
# - ASA unregistered               #
# - ASA doesn't own the objective  #
#  (for negotiation)               #
####################################
    if obj.neg and obj.synch:
        return errors.notBoth
    if sending_synch and not obj.synch:
        return errors.notSynch
    if _no_nonce(asa_nonce):
        return errors.noASA
    _obj_lock.acquire()
    if (obj.neg or sending_synch) and not([x for x in _obj_registry if x.objective.name == obj.name and x.asa_id == asa_nonce]):
        _obj_lock.release()
        return errors.notYourObj
    _obj_lock.release()

    return errors.ok

####################################
# Session ID cache functions       #
####################################

_prng = random.SystemRandom() # best PRNG we can get
def _new_session(locator):
    """Internal use only"""
####################################
# Create and insert a new Session  
# in state active, local           
# _new_session(locator) returns integer    
####################################
    _sess_lock.acquire()
    for i in range(10):
        #x = _prng.randint(0, 0xffffff) #old 24 bit version
        x = _prng.randint(0, 0xffffffff)
        # does _session_id_cache contain an id_value = x?
        if not([clash for clash in _session_id_cache if clash.id_value == x]):
            if locator == None:
                _session_id_cache.append(_session_instance(x,True,None))
            else:
                _session_id_cache.append(_session_instance(x,True,locator.packed))
            _sess_lock.release()
            return x
    # If we're here, something is deeply suspect and we have to give up.
    raise RuntimeError("Ten successive pseudo-random session ID clashes")




def _insert_session(session_inst, _check_race = False):
    """Internal use only"""
####################################
# Insert a Session ID entry        #
#                                  #
# return True if successful        #
#                                  #
# set _check_race to check for     #
# race condition                   #
####################################
    new_id = session_inst.id_value
    #check for a clash
    _sess_lock.acquire()
    
    if ([clash for clash in _session_id_cache if clash.id_value == new_id]):
        # duplicate, need to check source address
        _sess_lock.release()
        if _check_race:
            return False # incredibly unlikely race condition, do nothing
        clash = _get_session(_session_nonce(new_id,session_inst.id_source))
        #the following test is because in theory the session could have
        #just been deleted by another thread...
        if clash:
            if clash.id_source == session_inst.id_source:
                #now we have a confirmed clash, cannot continue
                return False
        #duplicate has a different source address (or it vanished)
        #so we can continue
        _sess_lock.acquire()
    session_ct = len(_session_id_cache)
    if session_ct >= _sessionCacheLimit:
        # try to free a space
        for i in range(session_ct):
            if not _session_id_cache[i].id_active:
                # found first inactive entry - delete it and append new one
                del _session_id_cache[i]
                _session_id_cache.append(session_inst)
                _sess_lock.release()
                return True
        # no free space, fail
        tprint("Session cache overflow!")
        _sess_lock.release()
        return False
    else:
        #append new one
        _session_id_cache.append(session_inst)
        _sess_lock.release()
        return True



def _get_session(snonce):
    """Internal use only"""
####################################
# Get a Session ID entry by ID and #
# source locator                   # 
#                                  #
# _get_session(_session_nonce)     #
# return False if not found active #
# else return _session_instance    #
####################################   
    _sess_lock.acquire()
    for s in _session_id_cache:
        if snonce.id_value == s.id_value and snonce.id_source == s.id_source and s.id_active:
            _sess_lock.release()
            return s
    _sess_lock.release()
    return False



def _update_session(session_inst):
    """Internal use only"""
####################################
# Update a Session ID entry        #
#                                  #
# return True if successful        #
####################################
    old_id = session_inst.id_value
    old_src = session_inst.id_source
    _sess_lock.acquire()
    session_ct = len(_session_id_cache)
    for i in range(session_ct):
        if old_id == _session_id_cache[i].id_value and old_src == _session_id_cache[i].id_source:
            _session_id_cache[i] = session_inst
            _sess_lock.release()
            return True
    #no such ID/source, fail
    _sess_lock.release()
    return False



def _disactivate_session(snonce):
    """Internal use only"""
####################################
# Disactivate a Session ID entry   #
#                                  #
# parameter is _session_nonce      #
#                                  #
# ignores mismatch                 #
# returns nothing                  #
####################################
    s = _get_session(snonce)
    if s:
        s.id_active = False
        _update_session(s)
    return

def _ass_obj(x):
    """Internal use only"""
######################################
# Assemble an objective ready for CBOR
######################################

    obj_flags = _flagword(x)
    _val = x.value
    if type(_val).__name__ == "bytes":
        #see if user supplied value as CBOR bytes
        try:
            _ = cbor.loads(x.value)
            #seems to be valid CBOR, build Tag 24
            _tag24 = cbor.cbor.Tag(tag=24)
            _length = len(_val)
            #be lazy, don't optimise CBOR encoding
            if  _length<65536:
                _tag24.value = bytes.fromhex('59')+_length.to_bytes(2,byteorder='big')+_val
                _val = _tag24
            else:
                #byte string too big, we'll send the raw bytes
                pass
        except:
            #not valid CBOR, we'll send the raw bytes
            pass
    return [x.name, obj_flags, x.loop_count, _val]


def _ass_message(msg_type, session_id, initiator, *whatever):
    """Internal use only"""
####################################
# Assemble a CBOR message          #
#                                  #
# returns CBOR bytes               #
####################################
    msg =[msg_type, session_id]

    # Insert initiator in Discovery, Response and Flood
    if msg_type in (M_DISCOVERY, M_RESPONSE, M_FLOOD):
        #msg.append(initiator.packed)
        msg.append(initiator)

    for x in whatever:
        if type(x).__name__ == "objective":
            #needs to be embedded as a list object
            #ttprint("ass_message Obj value:", x.value)
            msg.append(_ass_obj(x))
        elif type(x).__name__ == "list":
            if msg_type == M_FLOOD:
##                #wrong version - inserted extra level of nesting                
##                _stuff=[]
##                for y in x:                    
##                    _stuff.append([_ass_obj(y[0]),y[1]]) # objective & locator option
##                msg.append(_stuff)
                for y in x:
                    msg.append([_ass_obj(y[0]),y[1]]) # objective & locator option
            else:
                #lazy code: assume we have a valid embedded option
                #and insert as-is
                msg.append(x)                  
        elif msg_type in (M_WAIT, M_FLOOD, M_RESPONSE):
            msg.append(x) # insert timeout
        elif msg_type == M_INVALID:
            msg.append(x) # insert arbitrary content
            
        #more cases to be added if new GRASP messages or options are defined 
                
    ttprint("Assembled Python message", msg) 

    #Convert to CBOR bytes
    msg_bytes = cbor.dumps(msg)
    ttprint("Assembled CBOR message:",msg_bytes)
    return msg_bytes


def _detag_obj(x):
    """Internal use only"""
####################################
# If value is embedded CBOR, remove tagging.
# Call this before storing or returning
# a received objective.
# If called twice on the same objective,
# it is a no-op.
####################################

    try:
        if x.value.tag != 24:
            #wrong tag, return it as is
            return x
        _x = x.value.value
        #embedded bytes object, strip CBOR length metadata
        #(see RFC7049 to understand this)
        if _x[0] in range(0x40,0x57):
            #4 bit length
            _l = x[0] & 0x17
            _x = _x[1:]
        elif _x[0] == 0x58:
            #8 bit length
            _l = _x[1]
            _x = _x[2:]
        elif _x[0] == 0x59:
            #16 bit length
            _l = _x[2]+256*_x[1]
            _x = _x[3:]
        else:
            #lazy code: give up
            return x
        if len(_x) != _l:
            #the byte string was truncated or too long
            grasp.tprint("Corrupt Tag 24 byte string")
            x.value = b'\xf6' #best we can do is return a CBOR null           
        #now we have plain CBOR, we could try to decode it,
        #but that is better left to the ASA
        x.value = _x
    except:
        #no tag, return it as is
        pass
    return x

def tname(x):
    """-> name of type of x"""
    return type(x).__name__

def _check_diag(e):
    """Internal use only"""
#########################################
# Print diagnostic code for invalid syntax
#########################################
    global test_mode
    if test_mode:
        tprint("Check message error", e)

def _check_obj(obj):
    """Internal use only"""
#########################################
# Check if received objective is in valid
# format, after CBOR decoding.
#########################################
    if tname(obj) != 'list':
        _check_diag(1)
        return False #not a list
    if len(obj) not in (3,4):
        _check_diag(2)
        return False #invalid length
    if tname(obj[0]) != 'str' or \
       tname(obj[1]) != 'int' or \
       tname(obj[2]) != 'int':
        _check_diag(3)
        return False #wrong type
    #no rules about the value field, so nothing to check
    return True
        

def _check_opt(opt):
    """Internal use only"""
#########################################
# Check if received option is in valid
# format, after CBOR decoding.
#########################################
    if tname(opt) != 'list':
        _check_diag(4)
        return False #not a list
    elif not len(opt):
        _check_diag(5)
        return False #zero length
    if opt[0] == O_DIVERT:
        if len(opt) < 2 or \
          tname(opt[1]) != 'list':
            _check_diag(6)
            return False 
        else:
            #a bit lazy, did not check embedded locator options
            return True
    elif opt[0] == O_ACCEPT:
        return True
    elif opt[0] == O_DECLINE:
        if len(opt) == 1:
            return True
        elif len(opt) == 2 and tname(opt[1]) == 'str':
            return True
        else:
            _check_diag(7)
            return False
    elif opt[0] in (O_IPv6_LOCATOR, O_IPv4_LOCATOR):
        if len(opt) == 4:
            if tname(opt[1]) == 'bytes' and \
               tname(opt[2]) == 'int' and \
               tname(opt[3]) == 'int':
                return True
            else:
                _check_diag(8)
                return False
        else:
            return False
    elif opt[0] in (O_FQDN_LOCATOR, O_URI_LOCATOR):
        if len(opt) == 4:
            if tname(opt[1]) == 'str' and \
               (tname(opt[2]) == 'int' or tname(opt[2]) == 'NoneType') and \
               (tname(opt[3]) == 'int' or tname(opt[3]) == 'NoneType'):
                _check_diag(9)
                return True
            else:
                _check_diag(10)
                return False
        else:
            _check_diag(11)
            return False
    else:
        _check_diag(12)
        return False # unknown option
        

def _check_mess(payload):
    """Internal use only"""
#########################################
# Check if received message is in valid
# format, after CBOR decoding.
# Does not check content of options or objectives
#########################################
    if not mess_check:
        return True
    if tname(payload) != 'list':
        _check_diag(13)
        return False #not a list
    elif not len(payload):
        _check_diag(14)
        return False #zero length
    if payload[0] == M_NOOP:
        return True
    elif payload[0] == M_DISCOVERY:
        if len(payload) != 4 or \
           tname(payload[1]) != 'int' or \
           tname(payload[2]) != 'bytes' or \
           not _check_obj(payload[3]):
            _check_diag(15)
            return False
        else:
            return True
    elif payload[0] == M_RESPONSE:
        if len(payload) < 5 or \
           tname(payload[1]) != 'int' or \
           tname(payload[2]) != 'bytes' or \
           tname(payload[3]) != 'int' or \
           not _check_opt(payload[4]):
            _check_diag(16)
            return False 
        else:
            #only checked for minimal content 
            return True
    elif payload[0] == M_FLOOD:
        if len(payload) < 5 or \
           tname(payload[1]) != 'int' or \
           tname(payload[2]) != 'bytes' or \
           tname(payload[3]) != 'int' or \
           tname(payload[4]) != 'list':
            _check_diag(17)
            return False 
        else:
            #check embedded tagged objective
            if len(payload[4]) != 2:
                _check_diag(18)
                return False
            if not _check_obj(payload[4][0]):
                _check_diag(19)
                return False
            if len(payload[4][1]):
                if not _check_opt(payload[4][1]):
                    _check_diag(20)
                    return False
            #only checked for first content    
            return True        
    elif payload[0] in (M_REQ_NEG, M_NEGOTIATE, M_SYNCH, M_REQ_SYN):
        if len(payload) != 3 or \
           tname(payload[1]) != 'int' or \
           not _check_obj(payload[2]):
            _check_diag(21)
            return False
        else:
            return True
    elif payload[0] == M_END:
        if len(payload) !=3 or \
           tname(payload[1]) != 'int' or \
           not _check_opt(payload[2]):
            _check_diag(22)
            return False
        else:
            return True
    elif payload[0] == M_WAIT:
        if len(payload) != 3 or \
           tname(payload[1]) != 'int' or \
           tname(payload[2]) != 'int':
            _check_diag(23)
            return False
        else:
            return True
    else:
        #unknown message type
        _check_diag(24)
        return False

def _try_mcsock(ifi):
    """Internal use only"""
####################################################
# Service function for _make_mcssock etc.           #
####################################################    
    mcssock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) 
    mcssock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    mcssock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, struct.pack('@I', ifi))
    if not listen_self:
        #don't listen to yourself talking
        mcssock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 0)
    mcssock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)
    return mcssock

def _make_mcssock(ifi):
    """Internal use only"""
####################################################
# Create socket to send GRASP multicasts on a      #
# given interface                                  #
# (Discovery messages and Synchronisation flood    #
# messages) and handle them accordingly            #
####################################################

    _mcssocks.append([ifi, _try_mcsock(ifi)])

def _fixmcsock(i):
    """Internal use only"""
####################################################
# Fix socket to send GRASP multicasts on a         #
# given interface                                  #
# Called if socket fails when used.                #
####################################################

    _mcssocks[i][1].close()
    ifi = _mcssocks[i][0]
    while True:
        try:
            _mcssocks[i][1] = _try_mcsock(ifi)
            break
        except OSError:
            tprint("Waiting for interface") 
            time.sleep(5) # wait for interface to come back up

    # The TCP listening socket and thread is now broken and must be recreated.
    # Note: as coded 20160605, the broken thread is not garbage-collected.

    _init_drsocks(i)

class _mclisten(threading.Thread):
    """Internal use only"""
####################################################
# Listen for GRASP link-local multicasts           #
# (Discovery messages and synchronisation Flood    #
# messages) and queue them for handling            #
#                                                  #
# This runs as a thread                            #
####################################################
    def __init__(self):
        threading.Thread.__init__(self)
        
    def run(self):
        global _mc_restart
        mcrsock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        mcrsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        mcrsock.bind(('',GRASP_LISTEN_PORT))
        #join LL multicast group on all interfaces
        for x in _ll_zone_ids:
            mreq = ALL_GRASP_NEIGHBORS_6.packed + struct.pack('@I', x[0])
            while True:
                try:
                    mcrsock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
                    break
                except:
                    #failed, probably too soon during restart so wait & retry
                    time.sleep(2)
                    
        mcrsock.settimeout(120)

        tprint("LL multicast listener is up")
        while True:
            try:
                ttprint("Listening for LL multicasts")
                rawmsg, send_addr = mcrsock.recvfrom(GRASP_DEF_MAX_SIZE)
                if "%" in send_addr[0]:
                    a,b = send_addr[0].split('%')
                    saddr = ipaddress.IPv6Address(a)
                else:
                    saddr = ipaddress.IPv6Address(send_addr[0])
                sport = send_addr[1]
                ifn = send_addr[3]
                ttprint("Received multicast",rawmsg,"from",saddr,"port",sport,"interface",ifn)
                if listen_self or (not [ifn, saddr] in _ll_zone_ids):

                    #Because we listen to ourselves in testing
                    #and because we can't trust IPV6_MULTICAST_LOOP = 0                    
                        
                    try:
                        payload = cbor.loads(rawmsg)
                    except:
                        tprint("Multicast: CBOR decode error")
                        continue
                    if not _check_mess(payload):
                        #invalid message, cannot process it
                        tprint(payload)
                        tprint("Multicast: Invalid message format")
                        continue
                    ttprint("Multicast: CBOR->Python:", payload)
                    if payload[_Pl_Msg]==M_DISCOVERY or payload[_Pl_Msg]==M_FLOOD:
                        if _relay_needed:
                            #ttprint("Send",payload[_Pl_Msg],"from", ifn, "for relay")
                            _relay(payload,ifn)                         
                        try:
                            ##munge the format of the initiator address
                            #payload[_Pl_Ini] = ipaddress.IPv6Address(payload[_Pl_Ini])
                            ttprint("Initiator:", str(ipaddress.IPv6Address(payload[_Pl_Ini])))
                            #queue for the mc handler
                            _mcq.put([saddr, sport, ifn, payload],block=False)
                        except:
                            tprint("Multicast queue full: packet dropped")
                            pass
                    #note that unrecognized messages are simply ignored
            except OSError:
                tprint("No LL multicasts on interface for 2 minutes")
                if _mc_restart:
                    # Need to exit and restart if we can
                    _mc_restart = False
                    _mclisten().start()
                    break #restarted, so this one can exit
                else:
                    _mc_restart = True  #restart anyway next time
                                        #in case we missed a CPU wakeup
                

def _relay(payload, ifi):
    """Internal use only"""
####################################################
# Relay GRASP link-local multicasts (Discovery and #
# Flood messages) to all other interfaces          #
#                                                  #
# lazy code: only controls loops using loop count  #
# and doesn't throttle rate. Note that we must not #
# throttle in line here because that would block   #
# the multicast listener - instead we need to queue#
# the relays for a separate thread that implements #
# the throttle.                                    #
####################################################

    
    #r_snonce = _session_nonce(payload[_Pl_Ses],ipaddress.IPv6Address(payload[_Pl_Ini]))
    r_snonce = _session_nonce(payload[_Pl_Ses],payload[_Pl_Ini])
    
    # drop message if this is a looping relay
    sess = _get_session(r_snonce)
    if sess:
        if sess.id_relayed:
            ttprint("Dropping a looping relayed multicast")
            return
        else:
            #mark the session as relayed
            sess.id_relayed = True
            _update_session(sess)
            
    _mtype = payload[_Pl_Msg]

    if _mtype == M_FLOOD:
##        #Faulty version with extra level of nesting
##        obj = payload[_Pl_FCon][0][0] #first objective in flood
        obj = payload[_Pl_FCon][0] #first objective in flood
        #ttprint("1st obj in flood",obj)
    else:
        obj = payload[_Pl_Dobj] #discovery target
    
    obj[_Ob_LCt] -= 1       #decrement loop count
                            #fyi: this also decrements the count in the
                            #flood cache instance (blame Python)
    
    if obj[_Ob_LCt] > 0:
        #loop count not exhausted        
        if _mtype == M_FLOOD:
            #ttprint("relaying", obj[_Ob_Nam],"flood with loop ct", obj[_Ob_LCt])
            if not sess:
                #insert session id for the relayed copies
                news = _session_instance(r_snonce.id_value,True,r_snonce.id_source)
                news.id_relayed = True
                _insert_session(news)
            msg_bytes = cbor.dumps(payload)
            for i in range(len(_ll_zone_ids)):                
                ttprint("Flood relay for", obj[_Ob_Nam])
                if _ll_zone_ids[i][0] != ifi: # will skip the relay source interface
                    _mcssocks[i][1].sendto(msg_bytes,0,(str(ALL_GRASP_NEIGHBORS_6), GRASP_LISTEN_PORT))
            _disactivate_flood(r_snonce).start() #will disactivate session ID later
        elif _mtype == M_DISCOVERY:
            # reuse discover function in relay mode, but kick it off
            # as a separate thread with fresh copy of objective
            d_obj = objective(obj[_Ob_Nam])           
            d_obj.loop_count = obj[_Ob_LCt]
            #Note - the flags are encoded in obj[_Ob_Flg]
            #but we don't bother to decode them for discovery
            #nor do we copy the value
            _disc_relay(r_snonce, d_obj, ifi).start()
        return

class _disactivate_flood(threading.Thread):
    """Internal use only"""
    def __init__(self, snonce):
        threading.Thread.__init__(self)
        self.snonce = snonce
    def run(self):
        time.sleep(GRASP_DEF_TIMEOUT/500)
        ttprint("Disactivating flood session")
        _disactivate_session(self.snonce)

class _disc_relay(threading.Thread):
    """Internal use only"""
    def __init__(self, snonce, obj, ifi):
        threading.Thread.__init__(self)
        self.snonce = snonce
        self.obj = obj
        self.ifi = ifi
    def run(self):
        ttprint("Discovery relay for", self.obj.name, self.obj.loop_count)
        #set timeout to 1s per loop count 20170528
        discover(None, self.obj, _discTimeoutUnit*self.obj.loop_count, relay_ifi=self.ifi, relay_snonce=self.snonce)

def _init_drsocks(i):
    """Internal use only"""
####################################
# Initialise TCP sockets to receive#
# unicast Discovery responses      # 
####################################

    # Can't use a comprehension because we need the actual
    # list index in order select the correct socket.
    _msg_bytes = cbor.dumps([M_NOOP]) #No-op message
    for _ in range(10):
        try:
            _mcssocks[i][1].sendto(_msg_bytes,0,(str(ALL_GRASP_NEIGHBORS_6), GRASP_LISTEN_PORT))
            _port = _mcssocks[i][1].getsockname()[1]
            _s =socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            _s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                #ttprint("Binding",_port)
                _s.bind(('',_port))
            except:
                # Can't get the same port number, try again
                #ttprint("Couldn't bind")
                _s.close()              
                _mcssocks[i][1].close()
                ifi = _mcssocks[i][0]
                _mcssocks[i][1] = _try_mcsock(ifi)
                continue
            _drlt = _drlisten(_s, _ll_zone_ids[i][0])
            tprint("Starting a discovery TCP listener for interface", _s.getsockname(), _ll_zone_ids[i][0])
            _drlt.start()
            return
        except OSError as ex:
            ttprint(ex)
            #Network down, most likely, wait and retry
            tprint("Retrying to start discovery listener")
            time.sleep(10)
    # If we're here, something is deeply suspect and we have to give up.
    raise RuntimeError("Cannot get free port for discovery TCP listener")
    

class _drlisten(threading.Thread):
    """Internal use only"""
####################################################
# Listen for discovery responses on a given socket #
#                                                  #
# Socket must be bound to a port already           #
# This runs as a thread and exits after timeout.   #
#                                                  #
# This thread is invoked for the Discover function #
# and must not be activated otherwise.             #
####################################################
    def __init__(self, sock, ifi):
        threading.Thread.__init__(self)
        self.sock = sock
        self.ifi = ifi
    def run(self):
        tprint("Discovery response listener for interface",self.ifi,"is up") 
        while True:
            self.sock.listen(5)         
            try:
                ttprint("Listening for discovery response")
                asock, aaddr = self.sock.accept()
                # Note - can we safely use _recvraw() here?
                #rawmsg, send_addr = asock.recvfrom(GRASP_DEF_MAX_SIZE)
                rawmsg, send_addr = _recvraw(asock)
                asock.close() 
                if '%' in aaddr[0]:
                    a,b = aaddr[0].split('%') #strip any Zone ID
                else:
                    a = aaddr[0]
                send_addr=ipaddress.IPv6Address(a)
                #ttprint("Received TCP", rawmsg, "from", send_addr)
                try:
                    payload = cbor.loads(rawmsg)
                    ttprint("Received response: CBOR->Python:", payload)
                    if not _check_mess(payload):
                        ttprint("Invalid Response message: packet dropped")
                    elif payload[_Pl_Msg] != M_RESPONSE:
                        ttprint("Not a Response message: packet dropped")
                    else:
                        #find the correct session queue
                        sid=payload[_Pl_Ses]  # session ID
                        #sini=ipaddress.IPv6Address(payload[_Pl_Ini]) # session initiator
                        sini=payload[_Pl_Ini] # session initiator
                        s=_get_session(_session_nonce(sid,sini))
                        if s:
                            # (give up silently if no such session)
                            if s.id_dq:
                                # (give up silently if session has no queue)
                                #queue for the discovery response handler
                                try:
                                    ttprint("Queueing response")
                                    s.id_dq.put([send_addr,self.ifi,payload],block=False)
                                except:
                                    tprint("Discovery response queue full or absent: packet dropped")
                except:
                    tprint("Discovery response: CBOR decode error")
            except OSError as ex:
                tprint("Discovery response socket error", ex)
                pass     #keep trying anyway



class _mchandler(threading.Thread):
    """Internal use only"""
####################################################
# Multicast queue handler                          #
#                                                  #
# This runs forever as a thread.                   #
#                                                  #
# This version is lazy: Floods queue behind        #
# Discovery responses.                             #
####################################################
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        global _i_sent_it
        tprint("Multicast queue handler up")
        while True:
            mc = _mcq.get()
            ttprint("Multicast handler got something", mc)
            from_addr = mc[0]
            from_port = mc[1]
            from_ifi = mc[2]
            msg = mc[3]
            if (not test_mode) and (msg[_Pl_Msg] == M_DISCOVERY) and \
               (msg[_Pl_Ses] == _i_sent_it):
                # hack to ignore self-sent discoveries if multiple instances and
                # running with listen_self == True
                ttprint("Dropping own discovery multicast")
                
            elif msg[_Pl_Msg] == M_DISCOVERY:
                ttprint("Got multicast Discovery msg")
            
                if test_divert:
                    ttprint("mchandler: test_divert",test_divert)

                #Is the objective registered in this node?
                try:
                    oname = msg[_Pl_Dobj][_Ob_Nam]
                    _proto = False
                    if not test_divert:                        
                        _obj_lock.acquire()
                        for x in _obj_registry:
                            if x.objective.name == oname and x.discoverable:
                                #Yes, we have it, can send unicast response
                                _proto = x.protocol
                                _port = x.port
                                _ttl = x.ttl
                                _local = x.local
                                break
                        _obj_lock.release()
                    
                    if _proto:
                        #found it locally, respond immediately
                        if _local or (_my_address == None):
                            #either link-local address is required, or we
                            #have no global address, may as well send link-local
                            for y in _ll_zone_ids:                            
                                if y[0] == from_ifi:
                                    a = y[1].packed                              
                        else:
                            a = _my_address.packed
                        #build locator option (only supports IPv6)
                        lo = [O_IPv6_LOCATOR, a, _proto, _port]
                        #create TCP socket, assemble message and send it
                        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                        try:
                            #ttprint("Connecting",from_addr, from_port)
                            sock.connect((str(from_addr), from_port,0,from_ifi))
                            msg_bytes = _ass_message(M_RESPONSE, msg[_Pl_Ses], msg[_Pl_Ini],
                                                     _ttl, lo)
                            #ttprint("Sending",msg_bytes)
                            sock.sendall(msg_bytes,0)
                            ttprint("Sent local response")
                        except OSError as ex:
                            tprint("Socket error when sending local discovery Response", ex)
                        #we don't need this socket again
                        sock.close()
                        
                    else:
                                            
                        # Not local - do we have it in the cache?
                        # We will come here too if test_divert is set
                        
                        _disc_lock.acquire()
                        # Can't use a comprehension because we need the actual
                        # list entry in order to delete it.
                        ll = False
                        for i in range(len(_discovery_cache)):
                            x = _discovery_cache[i]                        
                            if x.objective.name == oname: #yes, we can send a Divert                            
                                del(_discovery_cache[i])
                                _discovery_cache.append(x)   #make it Most Recently Used
                                _disc_lock.release()
                                ll = x.asa_locators
                                break
                        if ll: #'ll' in locals():
                            #Build Divert option
                            ttprint("Build Divert option")
                            _ttl = 0
                            divo = [O_DIVERT]
                            for y in ll:
                                #ttprint("Discovery cache entry", y.is_ipaddress, y.locator, y.ifi, y.expire, int(time.monotonic()))
                                if y.is_ipaddress:
                                    if (not y.locator.is_link_local) and \
                                       (y.expire > int(time.monotonic())): #not LL and not expired                                    
                                                                   
                                        #build locator option (only supports IPv6, TCP)
                                        lo = [O_IPv6_LOCATOR, y.locator.packed, socket.IPPROTO_TCP, y.port]                                    
                                        divo.append(lo)
                                        if test_divert:
                                            break # to avoid duplicates during local testing
                                elif y.is_fqdn:
                                    divo.append([O_FQDN_LOCATOR, y.locator, y.protocol, y.port])
                                elif y.is_uri:
                                    divo.append([O_URI_LOCATOR, y.locator])
                                #calculate worst case TTL
                                if y.expire > 0:
                                    if _ttl > 0:
                                        _ttl = min(int((y.expire - time.monotonic())*1000),_ttl)
                                    else:
                                        _ttl = int((y.expire - time.monotonic())*1000)
                                
                            if _ttl == 0:
                                _ttl = _discCacheDefTimeOut  
                            if len(divo)>1:
                                #create TCP socket
                                sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                                try:
                                    sock.connect((str(from_addr), from_port,0,from_ifi))
                                    msg_bytes = _ass_message(M_RESPONSE, msg[_Pl_Ses], msg[_Pl_Ini],
                                                             _ttl, divo)
                                    sock.sendall(msg_bytes,0)
                                    ttprint("Sent divert response")
                                except OSError as ex:
                                    tprint("Socket error when sending divert Response", ex)
                                #we don't need this socket again
                                sock.close()
                        else:
                            _disc_lock.release()
                except:
                    #invalid discovery format - do nothing
                    tprint("Discovery message has invalid content")
            elif msg[_Pl_Msg] == M_FLOOD:
                ttprint("Got Flood message")

                try:
##                    #Faulty version with extra level of nesting
##                    lobjs = msg[_Pl_FCon] #list of [objective, locator]
                    lobjs = msg[_Pl_FCon:] #list of [objective, locator]
                except:
                    lobjs = [] # invalid, treat it as an empty flood
                    tprint("Flood message has invalid content")
                    
                #ttprint("List of [objective, locator]",lobjs)
                for lo in lobjs:
                    #sloppy code will crash if message malformed so...
                    try:
                        #construct asa_locator
                        _l = lo[1] 
                        if _l == []:
                            _loc = asa_locator(None, None, False)
                        else:
                            #lazy, not checking it's an address option
                            _loc = asa_locator(ipaddress.ip_address(_l[_Op_Con]), None, False)
                            _loc.is_ipaddress = True
                            _loc.protocol = _l[_Op_Proto]
                            _loc.port = _l[_Op_Port]
                        if msg[_Pl_TTL] > 0:
                            _loc.expire = int(time.monotonic() + msg[_Pl_TTL]/1000)
                        else:
                            _loc.expire = 0

                        #construct objective
                        obj = objective(lo[0][_Ob_Nam])
                        obj.loop_count = lo[0][_Ob_LCt]                        
                        #ttprint(obj.name,"flood has loop ct",obj.loop_count,"from ifi",from_ifi)
                        obj.value = lo[0][_Ob_Val]
                        obj = _detag_obj(obj)
                        #source = ipaddress.IPv6Address(msg[_Pl_Ini])
                        obj.neg, obj.synch, obj.dry = _flags(lo[0][_Ob_Flg])
                        if obj.synch: #must be a synch objective
                            _flood_lock.acquire()
                            #zap objective if already cached
                            #zap expired objectives as we go
                            for j in range(len(_flood_cache)):
                                if _flood_cache[j].objective.name == obj.name and \
                                   _flood_cache[j].source.locator == _loc.locator and \
                                   _flood_cache[j].source.port == _loc.port:
                                    #found it, zap old version
                                    _flood_cache[j] = None
                                    
                                elif _flood_cache[j].source.expire !=0 and \
                                     _flood_cache[j].source.expire < int(time.monotonic()):
                                    #expired entry, zap it
                                    #ttprint("MC handler expiring flood",_flood_cache[j].objective.name,
                                    #        _flood_cache[j].source.expire)
                                    _flood_cache[j] = None
                                    
                            #garbage collect
                            j=0
                            while j < len(_flood_cache):
                                if _flood_cache[j] == None:
                                    del _flood_cache[j]
                                else:
                                    j += 1
                            
                            #if cache is full, delete oldest
                            if len(_flood_cache) >= _floodCacheLimit:
                                del(_flood_cache[0])
                            #concatenate new one in MRU position
                            _flood_cache.append(tagged_objective(obj,_loc))    
                            _flood_lock.release()
                            #ttprint(obj.name,"flood appended")
                    except:
                        tprint("Got malformed Flood message, dropped it")                             
            else:
                # Some other message such as M_NOOP, drop it
                pass




class _tcp_listen(threading.Thread):
    """Internal use only"""
#########################################################
# TCP listener thread for synch and negotiate requests  #
#########################################################
    def __init__(self, listen_sock):
        threading.Thread.__init__(self)
        self.listen_sock = listen_sock

    def run(self):

        
        self.listen_sock.listen(5)
        self.listen_sock.settimeout(None) #listeners will block

        # For ever, wait for incoming connections and queue them
        # for the listening ASA (if any).
        ttprint("A TCP request listener is up on port", self.listen_sock.getsockname()[1])
        found = True #this will change if objective becomes unregistered
        while found:
            try:
                asock, aaddr = self.listen_sock.accept()
                asock.set_inheritable(True)
                ttprint("Talking on",asock.getsockname())
                # Note - can we safely use _recvraw() here?
                #rawmsg, send_addr = asock.recvfrom(GRASP_DEF_MAX_SIZE)
                rawmsg, send_addr = _recvraw(asock)
                if '%' in aaddr[0]:
                    a,b = aaddr[0].split('%') #strip any Zone ID
                else:
                    a = aaddr[0]
                send_addr=ipaddress.IPv6Address(a)
                #ttprint("Received TCP", rawmsg, "from", send_addr)
                try:
                    payload = cbor.loads(rawmsg)
                    ttprint("Received request: CBOR->Python:", payload)
                    if not _check_mess(payload):
                        tprint("Invalid Request message: packet dropped")
                        asock.close()
                    elif payload[_Pl_Msg] == M_INVALID:
                        tprint("Got M_INVALID", payload[_Pl_Ses],payload[_Pl_Con])
                        asock.close()
                    elif (payload[_Pl_Msg] != M_REQ_SYN) and (payload[_Pl_Msg] != M_REQ_NEG):
                        ttprint("Not a Request message: packet dropped")
                        asock.close()
                    else:
                        #check whether ASA is listening
                        queued = False
                        found = False
                        oname = payload[_Pl_Con][_Ob_Nam]
                        oflag = payload[_Pl_Con][_Ob_Flg]
                        _obj_lock.acquire()
                        for x in _obj_registry: #??? seems to fail in reentrant case?
                            if x.objective.name == oname:
                                found = True
                                ttprint("Listener found ",oname," listening=",x.listening)
                                if x.listening:
                                    #check that request matches synch or neg
                                    _neg,_synch,_dry = _flags(oflag)
                                    if not ((x.objective.neg == _neg) or
                                            (x.objective.dry == _dry) or 
                                            (x.objective.synch == _synch)):
                                        #oops, mismatch
                                        ttprint("Request mismatches capability")
                                        break                                
                                    #queue socket,sender,and message for the ASA
                                    try:
                                        x.listen_q.put([asock,send_addr,payload],block=False)
                                        queued = True
                                        ttprint("Request queued for ASA")
                                    except:
                                        tprint("ASA queue error: packet dropped")                            
                        _obj_lock.release()
                        if not queued:
                            # no listener for this objective
                            asock.close()
                except:
                    tprint("Listener: CBOR decode error")
                    asock.close()
            except OSError as ex:
                tprint("Request listener socket error", ex)
                pass     #go round again
        #if we get here, the objective has vanished
        ttprint("Listener exiting on port", self.listen_sock.getsockname()[1])
        self.listen_sock.close()
# end of TCP listener


def _get_my_address(build_zone=False):
    """Internal use only"""
####################################################
# Return my own valid global-scope IP address
# Build array of valid LL zones if requested
#
# This code is very o/s dependent
####################################################
    global _ll_zone_ids
    #ttprint("Entering _get_my_address",build_zone)
    _new_locator = None
    _new_ULA = None
    if os.name=="nt":
        #This only works on Windows
        _addrinfo = socket.getaddrinfo(socket.gethostname(),0)
        for _af,_temp,_temp,_temp,_addr in _addrinfo:
            if _af == socket.AF_INET6:
                _addr,_temp,_temp,_temp = _addr  #get first item from tuple
                if build_zone and ('%' in _addr):
                    _addr,_zid = _addr.split('%') #strip any Zone ID
                    _loc = ipaddress.IPv6Address(_addr)
                    if _loc.is_link_local:
                        _ll_zone_ids.append([_zid,_loc])
                if not '%' in _addr:
                    _loc = ipaddress.IPv6Address(_addr)
                    # Now test for GRUA or ULA address
                    if _loc.is_global and not _new_locator:
                        _new_locator = _loc # save first GRUA
                    if (_loc.is_private and not _loc.is_link_local) and not _new_ULA:
                        _new_ULA = _loc  # save first ULA
        if _new_ULA:
            _new_locator = _new_ULA       # prefer ULA

        #Windows-only hack to convert interface (Zone) IDs to indexes
        if build_zone:
            _ll_zone_ids = [[int(zid), loc] for zid, loc in _ll_zone_ids]
            
    else:
        #Jinmei's code for Posix operating systems

        if build_zone:
            for _iid, _ in socket.if_nameindex():
                with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as _s:
                    try:
                        _s.connect(('fe80::100', 4096, 0, _iid))
                        _addr = _s.getsockname()[0]
                        if '%' in _addr:
                            _addr, _zid = _addr.split('%') #strip any Zone ID
                            _loc = ipaddress.IPv6Address(_addr)
                            if _loc.is_link_local:
                                _ll_zone_ids.append([_zid, _loc])
                    except:
                        pass
            
            #Convert interface (Zone) IDs to indexes
            _ll_zone_ids = [[socket.if_nametoindex(zid), loc] for zid, loc in _ll_zone_ids]


        
        #Get own IPv6 address somewhat portably...
        #Needs testing on sleeping Linux...
        _s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        try:
            #This is a hack. We send a bogon to a site-local multicast
            #address (reserved by IANA for 'any private experiment').
            #Then we can find the sending address from the socket.
            #Note that this used to use a bogus global unicast address
            #('2001:db8:f000:baaa:f000:baaa:f000:baaa') but that fails in
            #case of a ULA prefix with no default IPv6 route.
            #
            #To find a non-hack solution, look for 'getnifs.py'
            
            _s.connect(('ff05::114', GRASP_LISTEN_PORT))
            _s.send(b'0',0)
        except:
            pass
        _sn = _s.getsockname()[0]
        _s.close()
        if (not '%' in _sn) and (_sn != '::'):
            _new_locator = ipaddress.IPv6Address(_sn)
            #it seems that on Linux this does not exclude LL addresses
            if _new_locator.is_link_local:
                _new_locator = None
    return _new_locator  


class _watcher(threading.Thread):
    """Internal use only"""
####################################################
# Keep an eye on the ACP for ever                  #
# (or for some time in test mode)                  #
#                                                  #
# In a production implementation, this thread would#
# monitor the active interfaces, add any new active#
# ones, and mark any old ones as inactive, updating#
# various data structures accordingly.             #
####################################################

    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        global _tls_required
        global _my_address
        global _mc_restart
        global _said_no_route
        time.sleep(1)
        tprint("ACP watcher is up; thread count:",threading.active_count())
        i=0
        while True:
            _tls_required = not(acp.status())
            time.sleep(10)
                       
            if test_mode and i<40:
                i += 1
                tprint("Watching the ACP in test mode; thread count:",threading.active_count())
##                for x in _obj_registry:
##                    if x.objective.value != 0:
##                        tprint(x.objective.name, "synch value", x.objective.value)
##                for x in _flood_cache:
##                    tprint(x.name, "flood value", x.value)
                if i == 40:
                    tprint("Watcher going silent")
                    
            # Watch for address change
            
            _new_locator = _get_my_address()
            if _new_locator == ipaddress.IPv6Address("::1"):
                # loopback address, looks like the CPU slept
                tprint("CPU wakeup, no address yet")
                # flag MC handler to restart on timeout
                _mc_restart = True
                # need to restart TCP listeners too                
                
            elif _new_locator and (_new_locator != _my_address):
                tprint("IPv6 address changed to",_new_locator)
                _my_address = _new_locator
                _said_no_route = False
                # flag MC handler to restart on timeout
                _mc_restart = True

            elif _new_locator == None:
                if not _said_no_route:
                    tprint("No routeable IPv6 address, using link local")
                    _said_no_route = True
                _my_address = None
                # flag MC handler to restart on timeout
                _mc_restart = True

def dump_all():
    """
    ####################################################
    # dump_all() prints the various data structures   
    #                                                 
    # Intended only for interactive debugging         
    # and not thread-safe                             
    ####################################################
    """
    print("\nThread count:",threading.active_count(),"\n------------")
    print("\nMy address:", str(_my_address),"\n----------")
    print("\nSession locator:", str(_session_locator),"\n---------------")
    print("\nLink local zone index(es):\n-------------------------")
    for x in _ll_zone_ids:
        print(x)
    print("\nASA registry contents:\n---------------------")       
    for x in _asa_registry:
        print(x.name,"nonce:",x.nonce)
    print("\nObjective registry contents:\n---------------------------")         
    for x in _obj_registry:
        o= x.objective
        print(o.name,"ASA:",x.asa_id,"Listen:",x.listening,"Port", x.port,"Neg:",o.neg,
               "Synch:",o.synch,"Count:",o.loop_count,"Value:",o.value)
    print("\nDiscovery cache contents:\n------------------------")
    for x in _discovery_cache:
        print(x.objective.name,"locators:")
        for y in x.asa_locators:
            print(y.locator, y.protocol, y.port, "Diverted:",y.diverted,"Expiry:",y.expire)
    print("\nFlood cache contents:\n--------------------")            
    for x in _flood_cache:
        print(x.objective.name,"count:",x.objective.loop_count,"value:", x.objective.value,
              "source:",x.source.locator, x.source.protocol, x.source.port, x.source.expire)
    print("\nSession ID cache contents:\n-------------------------")         
    for x in _session_id_cache:
        print("Nonce:",'{:8}'.format(x.id_value),"Source:",x.id_source,"Active:",x.id_active,
              "Relayed:",x.id_relayed)


def _initialise_grasp():
    """Internal use only """
    #Called the first time register_asa() is called

    ####################################
    # Should we even be here?          #
    ####################################
    
    global _grasp_initialised
    if _grasp_initialised:
        return
    
    ####################################
    # Declare all global variables     #
    # (a necessary nuisance)           #
    ####################################
    global _asa_registry
    global _asa_lock
    global _obj_registry
    global _obj_lock
    global _discovery_cache
    global _disc_lock
    global _session_id_cache
    global _sess_lock
    global _flood_cache
    global _flood_lock
    global _print_lock
    global _tls_required
    global _secure
    global _rapid_supported
    global _mcq
    global _drq
    global _my_address
    global _my_link_local
    global _session_locator
    global _ll_zone_ids
    global _said_no_route
    global _mcssocks
    global _relay_needed
    global _mc_restart
    global _i_sent_it
    global _skip_dialogue
    global test_mode
    global mess_check
    global listen_self
    global test_divert
    global _make_invalid
    global _make_badmess
    global _dobubbles

    ####################################
    ####################################
    #                                  #
    # Start of main initialisation     #
    #                                  #
    ####################################
    ####################################


    print("WARNING: This is insecure prototype code for the GRASP")
    print("protocol. It is unsuitable for operational purposes.")
    print("Use it at your own risk!")
    #print("For further details see http://xkcd.com/1742/")
    print("Python GRASP Version",_version,"released under the")
    print("simplified BSD license.")
    print("Will use port", GRASP_LISTEN_PORT)
    print("Will use multicast address", ALL_GRASP_NEIGHBORS_6)

    if not _skip_dialogue:
    
        ####################################
        # Run in test mode?                # 
        ####################################

        test_mode = False          # Set this True for prolix diagnostic prints
                                   # and some special case tests.
                                   # Leave it False for "production" mode.
        try:
            _l = input("Test mode (many extra diagnostics)? Y/N:")
            if _l:
                if _l[0] == "Y" or _l[0] == "y":
                    test_mode = True
        except:
            pass

        ####################################
        # Strict checking ?                # 
        ####################################

        mess_check = False         # Set this True for detailed format
                                   # checking for incoming messages
        try:
            _l = input("Strict inbound message checking? Y/N:")
            if _l:
                if _l[0] == "Y" or _l[0] == "y":
                    mess_check = True
        except:
            pass

        ####################################
        # Listen to own LL multicasts?     # 
        ####################################

        listen_self = False

        try:
            _l = input("Listen to own multicasts? Y/N:")
            if _l:
                if _l[0] == "Y" or _l[0] == "y":
                    listen_self = True
                    ttprint("WARNING: Will listen to own LL multicasts")
        except:
            pass
        
    ####################################
    # Initialise global variables      #
    #                                  #
    # Reminder: any of these that get  #
    # written before read inside any   #
    # function or thread must be       #
    # declared 'global' inside that    #
    # function.                        #
    ####################################

    _secure = False             # Not secure yet
    _tls_required = True        # Assume no ACP for now
    _rapid_supported = False    # Default, can only be changed by Intent
    _i_sent_it = 0              # Initialise hack to detect own discoveries
    
    _mcq = queue.Queue(_multQlimit) # Limits number of queued multicasts


    _asa_lock = threading.Lock()          # Create and acquire locks 
    _obj_lock = threading.Lock()
    _disc_lock = threading.Lock()
    _sess_lock = threading.Lock()
    _flood_lock = threading.Lock()
    _asa_lock.acquire()             # Acquire locks
    _obj_lock.acquire()
    _disc_lock.acquire()
    _sess_lock.acquire()
    _flood_lock.acquire()

    _asa_registry = []          # empty list of _asa_instance
    _obj_registry = []          # empty list of _registered_objective
    _discovery_cache = []       # empty list of _discovered_objective
    _session_id_cache = []      # empty list of _session_instance
    _flood_cache = []           # empty list of objective

    _asa_lock.release()         # Release locks
    _obj_lock.release()
    _disc_lock.release()
    _sess_lock.release()
    _flood_lock.release()

    _ll_zone_ids = []          # Empty list of [IPv6 Zone (interface) index,LL address]
    _mcssocks = []             # Empty list of multicast sending sockets
                               # Each entry is [Zone Index, socket]

    test_divert = False        # Flip this only inside test ASA, with care
    _make_invalid = False      # For testing M_INVALID, with care
    _make_badmess = False      # For testing bad message format, with care
                           
    tprint("Initialised global variables, registries and caches.")


    ####################################
    # Is there an ACP?                 #
    ####################################

    _secure = acp.status()
    tprint("ACP status is", _secure)
    _tls_required = not _secure
    if _tls_required:
        #should be code to cause TLS wrapping of TCP...
        tprint("WARNING: Need TLS, not implemented")

    ####################################
    # What's my address?               #
    # What interfaces do I have?       #
    ####################################

    _my_address = _get_my_address(build_zone=True)
    _said_no_route = False # flag used by watcher

    if _my_address == None:
        tprint("Could not find a valid global IPv6 address, will generate a bogon for session disambiguation")
        _p = bytes.fromhex('20010db8f000baaaf000baaa')       #96 bits of prefix
        _x = struct.pack('!L', _prng.randint(0, 2147483647)) #32 bits of randomness
        _session_locator = ipaddress.IPv6Address(_p+_x)
    else:
        _session_locator = _my_address
        
    tprint("My global scope address:", str(_my_address))
    tprint("Session locator:", str(_session_locator))
    tprint("Link local zone index(es):")
    for _x in _ll_zone_ids:
        tprint(_x)



    ####################################
    # Create sockets to send           #
    # LL multicasts                    # 
    ####################################

    for _x in _ll_zone_ids:    
        _make_mcssock(_x[0])

    #Those sockets are now waiting in _mcssocks[].
    #To send a packet:
    #_mcssocks[?][1].sendto(bytes.fromhex('f000baaa'),0,(str(ALL_GRASP_NEIGHBORS_6), GRASP_LISTEN_PORT))


    ####################################
    # Initialise TCP sockets to receive#
    # unicast Discovery responses      # 
    ####################################

    for _i in range(len(_ll_zone_ids)):
        _init_drsocks(_i)

    ####################################
    # Start relay if needed            #
    ####################################

    _relay_needed = False
    if len(_ll_zone_ids) > 1:
        # start thread to relay incoming Discovery and
        # Synchronisation multicasts
        _relay_needed = True
        tprint("Multicast relay needed")
    else:
        tprint("Multicast relay not needed")

    ####################################
    # Start threads to listen for and  #
    # handle GRASP multicasts          #
    # (Discovery and Flood messages)   #
    # on all interfaces                #
    ####################################


    # Start multicast _listener(s)
    _mc_restart = False
    _mclisten().start()
    # Start multicast queue handler
    _mchandler().start()
    ttprint("Set up multicast listening")


    ####################################
    # Start thread to keep an eye on   #
    # the ACP and need for TLS         #
    ####################################

    _watcher().start()
    ttprint("Set up ACP watcher")

    ####################################
    # GRASP initialisation complete!   #
    ####################################

    time.sleep(2) # to avoid printing glitch
    _grasp_initialised = True
    tprint("GRASP startup function exiting")

####################################
# Create globals needed for initialisation
####################################

_print_lock = threading.Lock() # printing might be needed before init!
test_mode = False              # referenced by skip_dialogue(), used by printing
listen_self = False            # referenced by skip_dialogue()
_skip_dialogue = False         # referenced by skip_dialogue()
_dobubbles = False             # Don't bubble print by default
bubbleQ = queue.Queue(100)     # Will be used if bubble printing

#------------------------------------------------------------
# The following are the GIF images used for the bubble printing
# mechanism. They are placed here only to avoid distraction
# elsewhere. Don't edit them! There's nothing significant below

_bigstring="""
R0lGODlhwgHIAOcAAAAAAAEBAQICAgMDAwQEBAUFBQYGBgcHBwgICAkJCQoKCgsLCwwMDA0NDQ4O
Dg8PDxAQEBERERISEhMTExQUFBUVFRYWFhcXFxgYGBkZGRoaGhsbGxwcHB0dHR4eHh8fHyAgICEh
ISIiIiMjIyQkJCUlJSYmJicnJygoKCkpKSoqKisrKywsLC0tLS4uLi8vLzAwMDExMTIyMjMzMzQ0
NDU1NTY2Njc3Nzg4ODk5OTo6Ojs7Ozw8PD09PT4+Pj8/P0BAQEFBQUJCQkNDQ0REREVFRUZGRkdH
R0hISElJSUpKSktLS0xMTE1NTU5OTk9PT1BQUFFRUVJSUlNTU1RUVFVVVVZWVldXV1hYWFlZWVpa
WltbW1xcXF1dXV5eXl9fX2BgYGFhYWJiYmNjY2RkZGVlZWZmZmdnZ2hoaGlpaWpqamtra2xsbG1t
bW5ubm9vb3BwcHFxcXJycnNzc3R0dHV1dXZ2dnd3d3h4eHl5eXp6ent7e3x8fH19fX5+fn9/f4CA
gIGBgYKCgoODg4SEhIWFhYaGhoeHh4iIiImJiYqKiouLi4yMjI2NjY6Ojo+Pj5CQkJGRkZKSkpOT
k5SUlJWVlZaWlpeXl5iYmJmZmZqampubm5ycnJ2dnZ6enp+fn6CgoKGhoaKioqOjo6SkpKWlpaam
pqenp6ioqKmpqaqqqqurq6ysrK2tra6urq+vr7CwsLGxsbKysrOzs7S0tLW1tba2tre3t7i4uLm5
ubq6uru7u7y8vL29vb6+vr+/v8DAwMHBwcLCwsPDw8TExMXFxcbGxsfHx8jIyMnJycrKysvLy8zM
zM3Nzc7Ozs/Pz9DQ0NHR0dLS0tPT09TU1NXV1dbW1tfX19jY2NnZ2dra2tvb29zc3N3d3d7e3t/f
3+Dg4OHh4eLi4uPj4+Tk5OXl5ebm5ufn5+jo6Onp6erq6uvr6+zs7O3t7e7u7u/v7/Dw8PHx8fLy
8vPz8/T09PX19fb29vf39/j4+Pn5+fr6+vv7+/z8/P39/f7+/v///yH+EUNyZWF0ZWQgd2l0aCBH
SU1QACH5BAEKAO8ALAAAAADCAcgAAAj+AN8JHEiwoMGDCBMqXMiwocOHECNKnEixosWLGDNq3Mix
o8ePIEOKHEmypMmTKFOqXMmypcuXMGPKnEmzps2bOHPq3Mmzp8+fQIMKHUq0qNGjSJMqXcq0qdOn
JAMEAEBVqtWrWAVo3cq1q9evYMOKHUu2rNmzaNOqXcu2rdu3cL8OGECgANSQVAEIWFBBw4cRKVi0
GEy4sOHDiBMrXsy4sePHkCNLnky5suXLmDNbZpGCxIcNFRoMyEvgbsW8BVA8qVPpFTFn1bR9E0e7
tu3buHPr3s27t+/fwIMLH068uPHjyJMrTw5umzVoxWZl0kNlhYK8ph1OBaDAxx9f5Oz+7evn75/5
8+jTq1/Pvr379/Djy59Pv779+/jz69/Pvz97f/3sY086xSwyBARU2ZXdQVMR0AEYtMSDnj/l+Wfh
hRhmqOGGHHboYYYVmocPL2+QYAAAByxIEFUglFEMPudR+OGMNNZo44045uhfiPpAM8cJVDWw4FQF
LGHKPOZRGKKOTDbp5JNQRhmfkubZk8sTCC5gmgAAQMCEMfxIKeaYZJZp5oYh5nNNGA8AkMBdVEUx
jD3/yHjmnXjmqeedFR6jxgFdPgUAATFUos+eiCaq6KI36kPLDAYEICgCahjD6KWYZqqpfdiwsQEA
GjTFZQSEYLPpqaimuqiM5TQCJAX+TVG1gSXjqGrrrbiOuY4oMATKFFUcYEJOrsQWa+yM65ASAwAR
NDVVsMMeK+201OKXbK8TOAsAtNV26+236V0LQAVJMMUlt+Cmq66x4lrAhLnbCrvuvPSmKi4GTsCL
br389puouBk8wdRo+/pr8MFkiqtBFEwREG+0CEcscZPicjBFIXoo5XDBE3fssYfidkAFxnlkfNTG
8n6s8soYiuuBFYToUbLJRRXwMMs455yfuB9cEXPJe9A81IkbpKzz0Ui7Jy4IVwwisx5Q51EU0UYn
bfXVS2PhdB5cQy00UFRDfPXYR4sbQhZbR801UWGT7bbOZqP9tNdQDwVo0WK/rXf+x+KKoIUgc3M9
s1B3V7334QiLO8Lfc8vcNeEA4I345ImT0uvigAuu9tc9FZ435aCvq/gWmXfteN1AeR766vOOLojp
m0udeuSGs247ta47PrPmQSFA++e3B1+s67DrzvlOvksu/PLsWg4ACaQXzztQydfO/PWoigt9IF3v
jsfa1P+O/fiqas/F6zPrXnLv4pPvvqbmA67HHvRHPT/7yr+v/6LaR5++/UELX/72R0A9xa97Xtud
AK1XwAbqynkkOB8C7SezBQLPgRiE0gFLlj4F/qR6F8ygCHW0wcZ50CcgHKEKn1TCDkbNgiuMIQkh
KEEOJvCFH2yfDHdIoxbesIL+ORwgD4e4IR9SUHYo1CERl9gyGqLPhDhMohCZSMX9GDFwMKyiFq3o
xAliMYgM3KIY4XPFE/YkhWNM43zKGMUzKlGNcGQPG4EoxTDGMY5zRKIbp3jHPuYxi30MpHn+CMYQ
CnKMhKyjIQ+5xUTu0Y6M1KIjeYLGSOKxizY8IiAtqcZJIu+NnBSjJ3VSyVAiEpNQpOMjF2nKIY4y
J6VspSRR6UJVUhKUsmTiK3ESy1zqkpY/1OMt+ehLVwJTk4Us5ix7FcEn1lKYnySmMmW4y5v0cpo7
rKZNronNGGqzJtzspgq/SZNwilOE5JyJOc+JwXTKZJ3sbKA7YwLPeBJwnjD+qac99YfPl+hzn+7r
p0v+CdDxCbQlBC3o9Q7KkoQqdHkMXYlDHxq8iKpkohS1nUVTgtGMrm6jKOmoR0EH0pOIdKSTK6lJ
TorSw6m0JCxtqd5eSpKYytRtNB2JTW86tpyKZKc8tZpPQwLUoCJtqCApqlHhdswvKnKpBm2qGYcJ
SaiSVKptpCorrZpSrNoymlXlKuKQ+hGlivVjZPWIWc/KN69Ck5S4ZCvl0tqRtco1YnTliF3verC8
bmSvfPWXXzUC2MDya7AZKaxh6YVYjCh2saJz6yYhu7fGXuSxlAWXZS2C2cx6a7MV6axnq7VB2HHw
rbC82WhnCkHS0S1oc2P+nwYqIY7Vkk1G6wjFCwBQgi44jW4UDIoDAPCAQFjDtm8jRyJKAAAYiIF7
gosu+H5iARSRYRhJQu7VrlGGChTAB2kARHShhofvoVYnBRBACRRBJ+1arR6rSMEAKpCFOvgBakGD
7eCEMhok1EIe7kWaP3TRBQEwIAdz6IPaajkUDHDHB7eoR3YD3DEZ3aMYUkDAAWpQhj3wQXPz2xxR
LhAAAszgEexI0pIo7K8KteMUNzAAAnZghvsab8HrK4rvIrCEXMRjSStmsbfsZB55GKMLEQDABYQw
Bz4EzXTde9xRNDAaCkQhFNm4h3qILORiBRkf4EAFGCwQgAbUIAxOPh3+iIGrFBH47gAr0IIjhIGO
INeHyzvCc5cxxA5kWCIML1BAAC6wAy/cwclQPt2Cj2cUDihAAANwwAiCUIZFtOIXyoiGNrzxjU57
+tPeAIc5tIym8vCDHeLg9KdXzepWu/rVsI61rGdN61rb+ta4zrWud83rXHtjG9NYRjBgIYk0GOEE
DoC0BGAghTfkQb823F0Cp+sUF2BgAaPJiwAQ0AAIeNvbEQg3BMTNAAuoARgYshM/fNEGEDzgAeGO
t7znTe962/ve+M63vvfN7377+98AD7jAB07wfkPAAQnINgACgAAKnGAIXqADHxQs3UTjOMfZicIQ
clADGHDmBChIQQr+VsACwbTgBSygwMK/0IsLhegcm7gBABhQAhvU4OY4zznOacDznvN8BkAHOg2C
TvSiG/3oSE+60pfO9KY7/elQj7rUp071qje9BjnwwRCSIIUvsMEOfPCDH2AL3GnbD3YqIkgf0mw8
wX2YDB8YgAY0sQ6Xm+cZebCAADhQhTh8uOKAD/x4o2Ze0wquvIgvr+AXz/jGO/7xkI+85CdP+cpb
fvLqwy/9+MD5+inaa7B9cgehnPaB/M+0evhDG4qQAAYwIRkWkpE8etGEusgADHn4cNl3z3ver7n3
wA++8IdP/OIb//jIT77yl8985QMexwB8muZMV3qC3Bi4f9ACCQD+kIJJmKNOdpYPlf5hjk2gQAAP
GMIa7nv6I97Q4u8f/efl3/z62//++M+//peP+hs/84fSp2aL9kzVVxC7E130Awc8kAAFQAXTACP7
ISP54AxmcAEAIAJRAHbuRzfS9j/AJ23ud1oguH8kWIImeIIo6HtRBoDEJ4IHWHbUV4AFETt5cF9N
8Ck2YAn7wB8Vwg6kMAMEgAA3MAbQlkorqD6n94ICmEn+B1wemIJQGIVSOIUceISNw4Ftd0QgOEH7
JYMGIW0etgYnQAAKwAfVMGF3dh74cA1qYIEckAR2oGBXOIdLeHYVd32fB32bQ4V82Id+GIWDt2bw
V0taOFVeOIP+JRMIbmAECoAAPMAL4Sd+5sEOp7ADB1AAMoBmoneFTOh7TkhBoGhCSUiIf1iKpniK
xic9g6dmhOiBpnWIDDE/gQAFn3ICj7BV/1Ee+zANa6AB25IEc0A/xUOHViiAmUd/gThtw4iKzNiM
zViMhreFUTZ60wOLDgEGJhAAD3AG4RAmevYeFZIOoCADBXAAMQAGfBA7Z5eHyJhJiSaCAdh2QCN6
hXd59niP+JiP+riP9vg9WhhieAhl0Zg+1igRLHAABIAFtnAfIRIPw4AFbcIBSCBxTyZ8T6hoLiRd
Kth/meeMHvmRf6iRZrdoofh5BUkRQqAABdACrSBhdSJ+IRL+DYEQAgLQADpABmkmPe/3gat4cVD0
ez45kiA5lESZgoJoeE54khhhBBUAACaQCLUyH0SGDp3QAwZQACuABYfWkQfYiZxojHnIjsGkk0JZ
lGZ5lvyHlEp5EhygjWYADjsIH1ymD7ogBgygZErgBjYGYhc5iEgZivK3loI5mEgRAgNQAFhwC2j4
Hy/5D/mgDHYQAgCwAGc2cdMImGUpfwNJmJzZmUdRAAXAAi25mOtRIftwDX7gAgCAACiQBXSwl6M4
gv5HjdPmmbZ5m8LllFA5JRUSDpTwAgZAACEQBXQAkAlkXjB4fdP3irjZnM6pE20SAWnwDXFZmkR2
DqogBCf+ggFCQJGrSH+7t5wd9JzkWZ400SYJcAbY1ZgTMpWkMAUL0CU6YAZ/sIkk2YlMeJHmuZ/8
2RJN6QBKQAwxkh7lUSHmIApHgCAQYAO4l45kqYxbyHv9OaEUehJcYgS6ICFbFiLoYApDkADEJQNo
8GyAeZRPyJdfVaEquqIZAQAD8AOfECbteR79kA6j8AQnwgAuAAbv4KBOOIrBJIqMxqJEWqQP4aIm
QAruMGEh4g/XQAlF0AAA0AAvsAUEAY9diYyseF5G2qVeehCjsQKNIDZE9gx8AAOAAgEwgBAoqpyn
hYVfGqdyihACEAAckAfrUCEhQg/MsAYiQBURkAMLEZT+90mQc3qoiOowD7AH0sCk6SALZGCBAAAr
DpGRMChliJqpcnoiFxAGjUqj0vAIRCABLpoBE8GJhqqpqhqno6EAXvCAVdILaFACDpMAILCquJqr
E+EwCAAGvmAe4HAKS4AgU6qrxnqsDdElToAM7UAMe2ADDhMAlIqs1FqtA8FwSpAJhPAEF8AlCGCt
4GqtCycBHKABJzIA4Zqu1JoXeZEi6vquurodAaAg8FqvuEoX9pqv+rqv/Nqv/vqvABuwAjuwBFuw
BnuwCJuwCruwDNuwDvuwEBuxEjuxFFuxFnuxGJuxGruxHNuxHvuxIBuyIjuyJFuyJnuyKJuyKruy
LNsqsi77sjAbszI7szRbszZ7szibszq7szzbsz77s0AbtEI7tERbtEYLEQEBADs="""

_bigstring2="""
R0lGODlhlgCbAIABAAAAAP///yH+D0lFVEYgR1JBU1AgMjAxNgAsAAAAAJYAmwAAAv6Mj6nL7Q+j
nLTai7PevPsPhuJIluaJpurKtu4Lx/JM1/aN5/qOAv4PDAJ4xIjwiEz+ijql8+lktqDUKlVKsmq3
SmyHCw4fvRex+ewjG9FstlrRjrffBrnd7b3r8cS9n4/zJ4iWM2goFniouHWz6GhV8yh5NTNpGSVz
qYmUuekJFPMpmvYyOlpqKuqSejrF+umqWjHIAvult7KZJZdr2TOXMomKGPzYCVa8aIN84ljI2KzY
VxV9yERtIo0FlW1N9tRNS9e1K04XkFRieJ4wVu7HDhf0Dh/fDjpibt8ruB9b748fwIC//hAUiOug
in4Kk+1pWPAhxGoSJ6ozaPHiwP6MITByzLfx4wePIkeSLHkrJEoNJ1duaOkyA8yYZVTKfEUqZUIP
OHNymImh5xCeNoP2NFlRJyukO5WmYnoHhFCodqQeJZr051WnvKia8hrHKk6wwLC+IgtI61izUdF6
cntG7Fm2VeFqsmsGry+6dbm24hsWsCzBaVlu9RtY7VzChY2uZUwIsS3IcSW/1RsmUVPLkSNlVbz5
WFvMmT2HfsmQRtGbQGt9Bn161WvUqUPNpr164W3DtYeNlps7Yt+O+mTHhr2b4nDixRF2BbnO+G/m
0V0f5/xc93XsiR0uF+FM+3To2pRn16gs3Hjy4dmfp2cMfHLS2y0Epz9fwn381Wwp7Ocv1HvmBdie
cwSWZ92B6UmnYH//NNjbgxDmp96E9XlnYXeiZViWahxq6OGHlWkmYmnPlMjMDihqsc2KmHzjIj7x
uKgQhx8pSNNXNDFwyY7+Necja8QESWSRRh6JZJJKLslkk04+CWUDBQAAOw=="""

#---------------The End ----------------------------------------------------
