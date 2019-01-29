
"""########################################################
########################################################
#                                                     
# Layer 2 Autonomic Control Plane (ACP)        
#                                                     
# Experimental version                              
#                                                     
# Module name is 'acp'
#                                                     
# This module provides an interface for GRASP to a Layer 2
# ACP, which is presumed to be intrinsically secure. It
# is intended to be used by the grasp.py implementation
# of GRASP.
#                                                     
# Because it's demonstration code written in an       
# interpreted language, performance is slow.          
#                                                     
# SECURITY WARNINGS:                                  
#  - assumes ACP up on all interfaces (or none)       
#  - assumes BUT DOES NOT CHECK that layer 2 is secured           
#  - does not watch for interface up/down changes
#    (but does handle IPv6 address changes)
#                                                     
# LIMITATIONS:                                        
#  - only coded for IPv6, any IPv4 is accidental
#  - survival of address changes and CPU sleep/wakeup is patchy          
#  - workarounds for defects in Python socket module and
#    Windows socket peculiarities. Not tested on Android.
#
# Released under the BSD 2-Clause "Simplified" or "FreeBSD"
# License as follows:
#                                                     
# Copyright (C) 2015-2019 Brian E. Carpenter.                  
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


# 20190126 restructure to put IP address/interface discovery
#          in the ACP module
#
# 20190129 exclude loopback interfaces on Windows

import os
import socket
import ipaddress

if os.name=="nt":  
    try:
        from scapy.all import get_windows_if_list
        _scapy = True
    except:
        _scapy = False
        print("Cannot find scapy, loopback interfaces may be included in ACP")

GRASP_LISTEN_PORT = 7017 # IANA port number

def new2019():
    """To detect out of date module"""
    return True

def status():
    """ACP status() """
    return "WARNING: Simple Layer 2 ACP with no security."

def _get_my_address(build_zone=False):
    """Get current address and build zone array"""
####################################################
# Return my own valid global-scope IP address
# Build array of valid LL zones if requested
#
# This code is very o/s dependent
####################################################

    _ll_zone_ids = []   # Empty list of [IPv6 Zone (interface) index,LL address]
    _loopbacks = []     # Empty list of loopback interfaces
    _new_locator = None
    _new_ULA = None
    if os.name=="nt":
        #This only works on Windows
        if build_zone and _scapy:
            #Find any loopback interfaces first
            _if_list = get_windows_if_list()
            for _if in _if_list:
                if 'Loopback' in _if['name'] or 'Loopback' in _if['description']:
                    _loopbacks.append(int(_if['win_index']))
                
        _addrinfo = socket.getaddrinfo(socket.gethostname(),0)
        for _af,_temp1,_temp2,_temp3,_addr in _addrinfo:
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

    
                
    if build_zone:
        #remove loopback interfaces
        i = 0
        while i < len(_ll_zone_ids):
            if _ll_zone_ids[i][0] in _loopbacks:
                del _ll_zone_ids[i]
            i += 1
        return _new_locator, _ll_zone_ids
    else:
        return _new_locator



    
