"""########################################################
########################################################
#                                                     
# Generic Autonomic Signaling Protocol (GRASP) API
#
# Module name is 'graspi'
#                                                     
# This is a prototype/demo implementation of an application
# programming interface for GRASP. It was developed using
# Python 3.7.
#
# The API is based on RFC8991. The implementation relies
# on the module grasp.py, which is based on RFC8990. 
# This code is not guaranteed or validated in any way and is 
# both incomplete and probably wrong. It makes no claim
# to be production-quality code. Its main purpose is to
# help improve the specifications.            
#                                                     
# Because it's demonstration code written in an       
# interpreted language, performance is slow.          
#                                                     
# SECURITY WARNINGS:                                  
#  - assumes ACP up on all interfaces (or none)
#  - does not watch for interface up/down changes
#  - no support for wrapping TCP in TLS      
#  - it is strongly recommended to use the built-in QUADS security
#    unless a truly secure ACP is available
#                                                     
# LIMITATIONS:                                        
#  - only coded for IPv6, no IPv4 support
#  - FQDN and URI locators incompletely supported          
#  - no code for handling rapid mode negotiation                         
#  - relay code is lazy (no rate control)                                      
#  - workarounds for defects in Python socket module and
#    Windows socket peculiarities. Not tested on Android.
#
# See grasp.py for license, copyright, and disclaimer.                         
#                                                     
########################################################
########################################################"""


import grasp
def init(self):
    pass

#First we import all the public classes, functions and
#data from grasp.py, which need no tweaking to conform
#to the API RFC-to-be.


_most = ['objective', 'asa_locator', 'tagged_objective',
            'register_asa', 'deregister_asa', 'register_obj',
            'deregister_obj', 'discover',
            'negotiate_wait',
            'end_negotiate', 'listen_negotiate', 'stop_negotiate',
            'send_invalid',
            'synchronize', 'listen_synchronize', 'stop_synchronize',
            'flood', 'get_flood', 'expire_flood',
            'skip_dialogue', 'tprint', 'ttprint', 'init_bubble_text',
            'dump_all',
            'errors', 'etext']

for t in _most:
    exec("from grasp import "+t+" as "+t)

#Next there are two functions where the returned values
#are defined differently in the RFC-to-be than in the
#original implementation. We therefore wrap calls to the
#old version to preserve backwards compatibility.
    
def request_negotiate(asa_handle, obj, peer, timeout):
    """
##############################################################
# request_negotiate(asa_handle, obj, peer, timeout)
#
# Request negotiation session with a peer ASA.
#
# asa_handle identifies the calling ASA
#
# obj is a GRASP objective including the requested value
#
# The objective's loop_count value should be set to a suitable
# value by the ASA. If not, the GRASP default will apply.
#
# peer is the target node, an asa_locator as returned by discover()
# If peer is None, discovery is performed first.
#
# timeout in milliseconds (None for default)
#
# Launch in a new thread if asynchronous operation required.
#
# Four possible return conditions are possible:
#
# 1) return zero, None, objective, None
#
# The peer has agreed; the returned objective contains the agreed value.
#
# 2) return zero, session_handle, objective, None
#
# Negotiation continues.
#
# The returned objective contains the first value offered by the
# negotiation peer. This instance of the objective MUST be used in
# subsequent negotiation steps because it contains the loop count.
#
# The ASA MUST store the session_handle (an opaque Python object)
# and use it in the subsequent negotiation steps.
# 
# 3) return errors.declined, None, None, string
#
# The peer declined further negotiation, the string gives a reason
# if provided by the peer.
#
# 4) For any non-zero errorcode except errors.declined:
#    return errorcode, None, None, None 
#
# The negotiation failed, errorcode gives reason,
# exponential backoff RECOMMENDED before retry.
##############################################################
"""
    e,s,r = grasp.req_negotiate(asa_handle, obj, peer, timeout)
    if e == errors.ok:
        return e, s, r, None
    if e == errors.declined:
        return e, None, None, r
    return e, None, None, None

def negotiate_step(asa_handle, shandle, obj, timeout):
    """
##############################################################
# negotiate_step(asa_handle, session_handle, objective, timeout)
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
# return: exactly like request_negotiate
##############################################################
"""
    e,s,r = grasp.negotiate_step(asa_handle, shandle, obj, timeout)
    if e == grasp.errors.ok:
        return e, s, r, None
    if e == grasp.errors.declined:
        return e, None, None, r
    return e, None, None, None

#Now define the exports from graspi as the direct imports
#plus those two wrapped functions.

__all__ = _most + ['request_negotiate', 'negotiate_step']

#Code that imports graspi can see through to other
#internals of grasp via (e.g.) graspi.grasp.test_divert
