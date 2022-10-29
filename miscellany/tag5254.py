#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""########################################################
#
# Build or decode and validate CBOR tags 52 & 54
#
# See grasp.py for license, copyright, and disclaimer.
#                                                     
########################################################"""

try:
    import cbor2 as cbor
    from cbor2 import CBORTag
except:
    import cbor
    from cbor import Tag as CBORTag
import math

#########################################
# A very handy function...
#########################################

def tname(x):
    """Returns name of type of x"""
    return type(x).__name__

#########################################
# Some very handy constants...
#########################################

bytemasks = [b'\x00',b'\x80',b'\xc0',b'\xe0',b'\xf0',b'\xf8',b'\xfc',b'\xfe',b'\xff']

####################################
# CBOR tag handling
####################################

def build5254(ipv, addr, plen, form = "prefix"):
    """Build Tag 52 or 54
    Inputs: IP version no., packed IP address/prefix (bytes), prefix length (int)
    Optional parameter form = "address", "prefix", or "interface"
    Returns: tagged CBOR item"""
    if ipv == 6:        
        _tag = CBORTag(54, None)
    elif ipv == 4:
        _tag = CBORTag(52, None)      
    else:
        return None
    if form == "address":
        _tag.value = addr
    elif form == "prefix":
        #remove unwanted bytes
        prefix = addr[:math.ceil(plen/8)]
        #detect covert bits in last byte
        if plen%8:
            if prefix[-1] != prefix[-1] & bytemasks[plen%8][0]:
                raise ValueError('Covert bits in prefix')            
        _tag.value = [plen, prefix]

    elif form == "interface":
        _tag.value = [addr, plen]
    return _tag



def detag5254(x):
    """Decode and validate tagged address or prefix
       Input: tagged CBOR item
       Returns IP version no., packed IP address/prefix, prefix length"""
    try:
        if x.tag == 54:
            ipv = 6
            asize = 16
        elif x.tag == 52:
            ipv = 4
            asize = 4
        else:
            raise ValueError('Wrong tag')
        v = x.value
        if tname(v) != 'list':
            #not an array, must be a plain address
            if tname(v) != 'bytes' or len(v) != asize:
                raise ValueError('Invalid address in tag')
            return ipv, v, None
        if tname(v[0]) == 'int':
            #must be a prefix spec [plen, address]
            #fill out the prefix to 16 or 4 byte
            plen = v[0]
            prefix = v[1]
            if tname(prefix) != 'bytes' or len(prefix) > asize:
                raise ValueError('Invalid prefix in tag')
            if plen < asize*8 and plen%8:
                if prefix[plen//8] & bytemasks[plen%8][0] != prefix[plen//8]:
                    raise ValueError('Covert bits in prefix')
            while len(prefix) < asize:
                prefix += b'\x00'
            return ipv, prefix, plen
        #must be an interface spec [address, plen]
        if tname(v[0]) != 'bytes' or len(v[0]) != asize:
            raise ValueError('Invalid address in tag')
        if not (v[1] <= asize*8 and v[1] > 0):
            raise ValueError('Invalid prefix length in tag')
        return(ipv, v[0], v[1])    
    except:
        raise #kick any exception up to the user

  
    
    
