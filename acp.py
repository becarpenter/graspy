
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
# of RFC8990. This module is *not* an implementation of
# RFC8994.
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
# See grasp.py for license, copyright, and disclaimer.                        
#                                                     
########################################################
########################################################"""


# 20190126 restructure to put IP address/interface discovery
#          in the ACP module
#
# 20190129 exclude loopback interfaces on Windows
#
# 20190131 faster method for finding loopbacks
#
# 20190205 make ULA preference work for Linux by using netifaces
#
# 20190206 bypass gap in older Python on Windows
#
# 20190207 deal with change in socket.getaddrinfo() in Python 3.7
#
# 20190721 handle netifaces import better
#
# 20190925 remove test for 'lo' in Posix branch
#
# 20191203 correct test for ULA
#
# 20200913 comment in status call how to indicate no security

import os
import socket
import ipaddress
import subprocess
import binascii

if os.name!="nt":
    try:
        import netifaces
    except:
        print("Could not import netifaces")
        time.sleep(10)
        exit()
    

GRASP_LISTEN_PORT = 7017 # IANA port number
_loopbacks = []     # Empty list of loopback interfaces

def new2019():
    """To detect out of date module"""
    return True

def status():
    """ACP status(), returns False if insecure """
    #return False #uncomment this line to tell the truth (ACP is insecure)
    return "WARNING: Simple Layer 2 ACP with no security." #tests as True

def _find_windows_loopbacks():
    """Internal use only"""
    #this detects bogus interfaces such as TunnelBear
    global _loopbacks
    result = []
    win_cmd = 'ipconfig'
    process = subprocess.Popen(win_cmd,
    shell=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE )
    for line in process.stdout:
        if line != b'\r\n' and line != b'Windows IP Configuration\r\n':
            result.append(bytearray.fromhex(line.hex()).decode())
    errcode = process.returncode

    inloopback = False
    inadaptor = False
    ignore = False
    for line in result:
        if line[0] != ' ':
            #new adaptor
            inloopback = False
            inadaptor = False
            ignore = False
            if 'oopback' in line:
                inloopback = True
        else:
            #in the body of an adaptor
            if 'Media disconnected' in line:
                ignore = True
            elif 'Link-local IPv6 Address' in line and inloopback and (not ignore):
                #find the interface index
                _, ifi = line.split('%')
                _loopbacks.append(int(ifi))

def is_ula(a):
    """Test for ULA"""
    return (a.is_private and not a.is_link_local
             and not a.is_loopback
             and not a.is_unspecified)

def _get_my_address(build_zone=False):
    """Get current address and build zone array"""
####################################################
# Return my own valid global-scope IP address
# Build array of valid LL zones if requested
#
# This code is very o/s dependent
####################################################
    global _loopbacks
    _ll_zone_ids = []   # Empty list of [IPv6 Zone (interface) index,LL address]
    _new_locator = None
    _new_ULA = None
    if os.name=="nt":
        #This only works on Windows

        #This needs recent Python
        try:
            _find_windows_loopbacks()
        except:
            pass
                
        _addrinfo = socket.getaddrinfo(socket.gethostname(),0)
        for _af,_temp1,_temp2,_temp3,_addr in _addrinfo:
            if _af == socket.AF_INET6:
                _addr,_temp,_temp,_zid = _addr  #get first item from tuple
                if '%' in _addr:
                    #this applies on Windows for Python before 3.7
                    _addr,_zid = _addr.split('%') #strip any Zone ID
                    _zid = int(_zid)
                if build_zone:
                    _loc = ipaddress.IPv6Address(_addr)
                    if _loc.is_link_local:
                        _ll_zone_ids.append([_zid,_loc])
                if not '%' in _addr:
                    _loc = ipaddress.IPv6Address(_addr)
                    # Now test for GRUA or ULA address
                    if _loc.is_global and not _new_locator:
                        _new_locator = _loc # save first GRUA
                    if is_ula(_loc) and not _new_ULA:
                        _new_ULA = _loc  # save first ULA
        if _new_ULA:
            _new_locator = _new_ULA       # prefer ULA
            
    else:
        
##       if build_zone:
##            #Jinmei's code for Posix operating systems
##            for _iid, _ in socket.if_nameindex():
##                with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as _s:
##                    try:
##                        _s.connect(('fe80::100', 4096, 0, _iid))
##                        _addr = _s.getsockname()[0]
##                        if '%' in _addr:
##                            _addr, _zid = _addr.split('%') #strip any Zone ID
##                            _loc = ipaddress.IPv6Address(_addr)
##                            if _loc.is_link_local:
##                                _ll_zone_ids.append([_zid, _loc])
##                    except:
##                        pass

        ifs = netifaces.interfaces()
        for interface in ifs:
            config = netifaces.ifaddresses(interface)
            #if interface != 'lo' and netifaces.AF_INET6 in config.keys():
            #(removed because assigning a ULA to 'lo' is reasonable practice)
            if netifaces.AF_INET6 in config.keys():
                for link in config[netifaces.AF_INET6]:
                    if 'addr' in link.keys():
                        _addr = link['addr']
                        if build_zone and '%' in _addr:
                            _addr, _zid = _addr.split('%') #strip any Zone ID
                            _loc = ipaddress.IPv6Address(_addr)
                            if _loc.is_link_local:
                               _ll_zone_ids.append([_zid, _loc])

                        if not '%' in _addr:
                            _loc = ipaddress.IPv6Address(_addr)
                            # Now test for GRUA or ULA address
                            if _loc.is_global and not _new_locator:
                                _new_locator = _loc # save first GRUA
                            if is_ula(_loc) and not _new_ULA:
                                _new_ULA = _loc  # save first ULA
                if _new_ULA:
                    _new_locator = _new_ULA       # prefer ULA
                        
        if build_zone:
            #Convert interface (Zone) IDs to indexes
            _ll_zone_ids = [[socket.if_nametoindex(zid), loc] for zid, loc in _ll_zone_ids]


        
##        #Get own IPv6 address somewhat portably...
##        #Needed if using jinmei's method
##        _s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
##        try:
##            #This is a hack. We send a bogon to a site-local multicast
##            #address (reserved by IANA for 'any private experiment').
##            #Then we can find the sending address from the socket.
##            #Note that this used to use a bogus global unicast address
##            #('2001:db8:f000:baaa:f000:baaa:f000:baaa') but that fails in
##            #case of a ULA prefix with no default IPv6 route.
##            #
##            #To find a non-hack solution, use the netifaces module
##            
##            _s.connect(('ff05::114', GRASP_LISTEN_PORT))
##            _s.send(b'0',0)
##        except:
##            pass
##        _sn = _s.getsockname()[0]
##        _s.close()
##        if (not '%' in _sn) and (_sn != '::'):
##            _new_locator = ipaddress.IPv6Address(_sn)
##            #it seems that on Linux this does not exclude LL addresses
##            if _new_locator.is_link_local:
##                _new_locator = None

    
                
    if build_zone:
        #remove any loopback interfaces detected earlier
        i = 0
        while i < len(_ll_zone_ids):
            if _ll_zone_ids[i][0] in _loopbacks:
                del _ll_zone_ids[i]
            i += 1
        return _new_locator, _ll_zone_ids
    else:
        return _new_locator



    
