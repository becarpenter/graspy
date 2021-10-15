#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""########################################################
########################################################
# pfxm4 is a demonstration Autonomic Service Agent.
# It supports the IPv6 Edge Prefix Management
# objective 'PrefixManagerT' and its companion
# 'PrefixManager.Params' for IPv6 and IPv4, but NOT as
# specified in RFC8992. This version uses CBOR tags
# 52 and 54 as per draft-ietf-cbor-network-addresses
#
# As demonstration code it does not operate in real
# prefix-assigning nodes or perform real prefix assignments.
#
# See grasp.py for license, copyright, and disclaimer.
#                                                     
########################################################"""

import grasp
import threading
import time
import datetime
try:
    import cbor2 as cbor
    from cbor2 import CBORTag
except:
    import cbor
    from cbor import Tag as CBORTag
import ipaddress
import struct
import binascii
import math

###################################
# Print current pool
###################################

def prefstr(plen,pref):
    if pref[:12] == mappedpfx:
        return str(ipaddress.IPv4Address(pref[12:]))+"/"+str(plen-96)
    else:
        return str(ipaddress.IPv6Address(pref))+"/"+str(plen)

def pref4str(plen,pref):
    return str(ipaddress.IPv4Address(pref))+"/"+str(plen)

def dump_pool():
    """Print prefix pool"""
    grasp.tprint("Prefix pool contents:")
    pool_lock.acquire()
    if len(ppool) == 0:
        grasp.tprint("(empty)")
    else:
        for x in ppool:
            grasp.tprint(prefstr(x[0],x[1]))
    pool_lock.release()
    return

###################################
# Print delegated prefixes
###################################

def dump_delegates():
    """Print delegated prefixes"""
    grasp.tprint("Delegated prefixes:")
    if len(delegated) == 0:
        grasp.tprint("(none)")
    else:
        for x in delegated:
            grasp.tprint(prefstr(x[0],x[1]))
    return

###################################
# Print obj_registry and flood cache
###################################

def dump_some():
    """Print obj_registry and flood cache"""
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
    return

#########################################
# A very handy function...
#########################################

def tname(x):
    """-> name of type of x"""
    return type(x).__name__

#########################################
# Some very handy constants...
#########################################

bytemasks = [b'\x00',b'\x80',b'\xc0',b'\xe0',b'\xf0',b'\xf8',b'\xfc',b'\xfe',b'\xff']

####################################
# CBOR tag handling
####################################

def build5254(ipv, addr, plen, form = "prefix"):
    """build Tag 52 or 54"""
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
        _tag.value = [plen, prefix]

    elif form == "interface":
        _tag.value = [addr, plen]
    return _tag



def detag5254(x):
    """decode tagged address or prefix
       --> version, addr, prefix length"""
    try:
        if x.tag == 54:
            ipv = 6
            asize = 16
        elif x.tag == 52:
            ipv = 4
            asize = 4
        else:
            return (None, None, 0) #wrong tag
        v = x.value
        if tname(v) != 'list':
            #not an array, must be a plain address
            return ipv, v, None
        if tname(v[0]) == 'int':
            #must be a prefix spec [plen, address]
            #fill out the prefix to 16 or 4 bytes
            prefix = v[1]
            if prefix[v[0]//8] & bytemasks[v[0]%8][0] != prefix[v[0]//8]:
                grasp.ttprint(v[0],prefix)
                return (None, None, 2) #extra bits in prefix
            while len(prefix) < asize:
                prefix += b'\x00'
            return ipv, prefix, v[0]
        #must be an interface spec [address, plen]
        return(ipv, v[0], v[1])    
    except:
        return (None, None, 1) #no tag or format error


####################################
# Thread to flood PrefixManager.Params repeatedly
####################################

class flooder(threading.Thread):
    """Thread to flood PrefixManager.Params repeatedly"""
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        grasp.tprint("Flooding", obj2.name, "for ever")
        while True:
            time.sleep(60)
            grasp.flood(asa_nonce, 59000, grasp.tagged_objective(obj2,None))
            time.sleep(5)

####################################
# Main negotiator
####################################

class main_negotiator(threading.Thread):
    """Main negotiator"""

    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):

        grasp.tprint("Ready to negotiate", obj1.name, "as listener, unless pool is empty")

        while True:
            if len(ppool) > 0:
                #attempt to listen for negotiation
                err, snonce, answer = grasp.listen_negotiate(asa_nonce, obj1)
                if err:
                    grasp.tprint("listen_negotiate error:",grasp.etext[err])
                    time.sleep(5) #to calm things if there's a looping error
                else:
                    #got a new negotiation request; kick off a separate negotiator
                    #so that multiple requests can be handled in parallel
                    negotiator(snonce,answer).start()
            else:
                time.sleep(5) #hoping the pool will refill
                              #(during this time, negotiation requests
                              # will fail with 'noPeer')

####################################
# Support function for negotiator
####################################

def endit(snonce, r):
    """Support function for negotiator"""
    grasp.tprint("Failed", r)
    err = grasp.end_negotiate(asa_nonce, snonce, False, reason=r)
    if err:
        grasp.tprint("end_negotiate error:",grasp.etext[err])
    return
            
####################################
# Thread to handle a PrefixManager negotiation
####################################


class negotiator(threading.Thread):
    """Thread to negotiate PrefixManager as server"""
    def __init__(self, snonce, nobj):
        threading.Thread.__init__(self)
        self.snonce = snonce
        self.nobj = nobj

    def run(self):
        nobj=self.nobj
        snonce=self.snonce
        try:
            nobj.value=cbor.loads(nobj.value)
            grasp.tprint("CBOR value decoded")
            _cbor = True
        except:
            _cbor = False

        req_ipv, _, req_plen = detag5254(nobj.value)

        if not req_ipv:
            endit(snonce, "Bad tag "+str(req_plen))
        else:
            grasp.tprint("Got request for IPv"+str(req_ipv)+"; length=", req_plen)
            if nobj.dry:
                grasp.tprint("Dry run (not handled by this implementation)")
            result=True
            reason=None       

            if len(ppool) == 0:
                endit(snonce, "Prefix pool empty")
            elif req_ipv == 6:
                if req_plen < 32 or req_plen > subnet_max:
                    endit(snonce, "Prefix length out of range")
                else:
                    pref = get_from_pool(req_plen)
                    if not pref:
                        #other end wants too much, we try to make an offer
                        while (not pref) and (req_plen < subnet_max):
                            req_plen +=1
                            pref = get_from_pool(req_plen)
                    if pref:
                        nobj.value = build5254(6, pref, req_plen)
                        grasp.tprint("Starting negotiation")
                        #we are offering the shortest prefix we can, so no
                        #negotiation loop can happen
                        grasp.tprint("Offering", prefstr(req_plen,pref))
                        if _cbor:
                            nobj.value=cbor.dumps(nobj.value)
                        err,temp,nobj = grasp.negotiate_step(asa_nonce, snonce, nobj, 1000)
                        grasp.ttprint("Step gave:", err, temp, nobj)
                        if (not err) and temp==None:
                            grasp.tprint("Negotiation succeeded") 
                        elif not err:
                            #we don't have enough resource, we will reject
                            insert_pool(req_plen, pref)
                            endit(snonce, "Insufficient resource")
                        else:    
                            #other end rejected or loop count exhausted
                            insert_pool(req_plen, pref)
                            if err==grasp.errors.loopExhausted:
                                # we need to signal the end
                                endit(snonce, "Loop count exhausted")
                            else:
                                grasp.tprint("Failed:", grasp.etext[err])
                        #end of negotiation 
                    else:
                        #got nothing suitable from pool
                        endit(snonce, "No prefix available")
            elif req_ipv == 4:
                if req_plen < 16 or req_plen > 32:
                    endit(snonce, "Prefix length out of range")
                else:
                    pref = get4_from_pool(req_plen)
                    if pref:
                        nobj.value = build5254(4, pref[12:], req_plen)
                        grasp.tprint("Starting negotiation")
                        #we are offering the shortest prefix we can, so no
                        #negotiation loop can happen
                        grasp.tprint("Offering", pref4str(req_plen,pref[12:]))
                        if _cbor:
                            nobj.value=cbor.dumps(nobj.value)
                        err,temp,nobj = grasp.negotiate_step(asa_nonce, snonce, nobj, 1000)
                        grasp.ttprint("Step gave:", err, temp, nobj)
                        if (not err) and temp==None:
                            grasp.tprint("Negotiation succeeded") 
                        elif not err:
                            #we don't have enough resource, we will reject
                            insert_pool(req_plen, pref)
                            endit(snonce, "Insufficient resource")
                        else:    
                            #other end rejected or loop count exhausted
                            insert_pool(req_plen, pref)
                            if err==grasp.errors.loopExhausted:
                                # we need to signal the end
                                endit(snonce, "Loop count exhausted")
                            else:
                                grasp.tprint("Failed:", grasp.etext[err])
                        #end of negotiation 
                    else:
                        #got nothing suitable from pool
                        endit(snonce, "No prefix available")
            
                
#end of a negotiating session

###################################
# Thread to delegate prefixes to clients.
# (Not activated in the origin)
#
# This version is a simulation. At random
# intervals, it gets a prefix from the
# pool and 'delegates' it by adding to
# a list.
###################################

delegated = []

class delegator(threading.Thread):
    """Thread to delegate prefixes"""
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        if quickly:
            grasp.tprint("Prefix delegator running quickly")
        else:
            grasp.tprint("Prefix delegator running slowly")
        while True:
            if quickly:
                time.sleep(1)
            else:
                time.sleep(grasp._prng.randint(10,60))
            p=get_from_pool(subnet_length)
            if p == None:
                nudge_pool(subnet_length)
            else:
                delegated.append([subnet_length,p])
            p=get4_from_pool(26)
            if p:
                delegated.append([122,p])
            _l = len(delegated)
            if _l == 1:
                grasp.tprint("1 prefix was delegated")
            if _l > 1:
                if (not quickly) or (not _l%10):
                    grasp.tprint(_l,"prefixes were delegated")

            if (not quickly) and grasp.test_mode:
                dump_delegates()

###################################
# Functions for prefix manipulation
###################################



def make_mask(plen):
    """-> bytes object that is a mask of plen bits"""
    
    mask = b''
    for i in range(0,plen//8):
        mask += b'\xff'
    mask += bytemasks[plen%8]
    while len(mask)<16:
        mask += b'\x00'
    return mask    

def mask_prefix(plen,prefix):
    """-> packed prefix masked to length plen"""

    m = make_mask(plen)    
    r = b''
    for i in range(0,16):
        r += bytes([(prefix[i]&m[i])%256])
    return r

bitmasks = [1,128,64,32,16,8,4,2]
bitvals = (1,2,4,8,16,32,64,128)

def split_prefix(plen, prefix):
    """-> plen+1, prefix1, plen+1, prefix2"""
    #Find last non-zero bit
    lb = 127
    for i in range(15,-1,-1):
        if prefix[i] == 0:
            lb -= 8
        else:
            for j in bitvals:
                if not j & prefix[i]:
                    lb -= 1
                else:
                    break
            break
    #grasp.ttprint("Last non-zero bit is",lb)
    #Check for valid split point
    if plen > 127 or plen <= lb:
        grasp.tprint("Cannot split prefix", prefstr(plen,prefix)) 
        raise RuntimeError("Unsplittable prefix")
    new_plen = plen + 1
    new_pref = b''
    j = plen//8
    for i in range(0,j):
        new_pref += bytes([prefix[i]])      
    new_pref += bytes([prefix[j] | bitmasks[new_plen%8]])
    while len(new_pref)<16:
        new_pref += b'\x00'
    return new_plen, prefix, new_plen, new_pref


####################################
# Functions to manage prefix pool
####################################

ppool = [] #empty pool
pool_lock = threading.Lock()

need = 0   #needed prefixes (counted in /'subnet_length's)
           #not relevant in origin
    
def create_pool():
    """makes a prefix pool, called only in origin"""
    #This is only for demonstration. A real version
    #would input a prefix from the NOC by some mechanism TBD
    #and would need to save persistent state
    
    ini_pref = [32,bytes.fromhex('20010db8000000000000000000000000')]
    try:
        _ = input("Choose IPv6 prefix for pool? Y/N:")
        if _[0] == "Y" or _[0] =="y":
            ini_pref = None
    except:
        pass
    if ini_pref == None:
        #Manual input needed        
        pl = 0
        while pl < 3 or pl > 127:
            try:
                _ = input("IPv6 prefix length for pool (3..127):")
                pl = eval(_)
            except:
                pass
        try:
            pp = bytes.fromhex('20010db8000000000000000000000000')
            _ = input("Manual prefix entry? Y/N:")
            if _[0] == "Y" or _[0] =="y":
                pp = None
                while pp==None:
                    _ = input("Enter IPv6 prefix:>")
                    try:
                       pp = ipaddress.IPv6Address(_).packed
                    except:
                        print("Invalid")                    
        except:
            pass
        ini_pref =[pl,pp]
    pool_lock.acquire()
    ppool.append(ini_pref)
    pool_lock.release()

    do4 = True
    try:
        _ = input("Support IPv4? Y/N:")
        if not (_[0] == "N" or _[0] =="n"):
            do4 = False
    except:
        pass
    if do4:
        ini_pref4 = [104,ipaddress.IPv6Address("::ffff:10.0.0.0").packed]
        pool_lock.acquire()
        ppool.append(ini_pref4)
        pool_lock.release()
        print("Created IPv4 (Net 10) pool")
    return

mappedpfx = bytes.fromhex('00000000000000000000ffff')

def get_from_pool(plen):
    """-> packed IPv6 prefix of requested length, or None"""
    pool_lock.acquire()
    #since pool is in descending order, search from the end backwards
    for i in range(len(ppool)-1,-1,-1):
        if ppool[i][0] > 103:
            #might be IPv4
            if ppool[i][1][:12] == mappedpfx:
                #skip if IPv4
                continue
        if ppool[i][0] == plen:
            #found one of the requested length
            r = ppool[i][1]
            del ppool[i]
            pool_lock.release()
            return r
        elif ppool[i][0] < plen:
            #found a longer one, split as necessary
            nl,p1,_,p2 = split_prefix(ppool[i][0], ppool[i][1])
            del ppool[i]
            pool_lock.release()
            insert_pool(nl,p1)
            if nl == plen:
                #correct length
                return p2
            else:
                #need to split again by recursion
                insert_pool(nl,p2)
                return get_from_pool(plen)
    pool_lock.release()
    return None

def get4_from_pool(plen4):
    """-> packed IPv4-mapped prefix of requested length, or None"""
    plen = plen4 + 96
    pool_lock.acquire()
    #since pool is in descending order, search from the end backwards
    for i in range(len(ppool)-1,-1,-1):
        if ppool[i][1][:12] == mappedpfx:
            #found mapped IPv4            
            if ppool[i][0] == plen:
                #found one of the requested length
                r = ppool[i][1]
                del ppool[i]
                pool_lock.release()
                return r
            elif ppool[i][0] < plen:
                #found a longer one, split as necessary
                nl,p1,_,p2 = split_prefix(ppool[i][0], ppool[i][1])
                del ppool[i]
                pool_lock.release()
                insert_pool(nl,p1)
                if nl == plen:
                    #correct length
                    return p2
                else:
                    #need to split again by recursion
                    insert_pool(nl,p2)
                    return get4_from_pool(plen - 96)
    pool_lock.release()
    return None

def insert_pool(plen, prefix):
    """inserts IPv6 prefix in pool in canonical order"""
    pool_lock.acquire()
    if len(ppool) > 0:
        #Are there prefixes of this length?
        for i in range(len(ppool)):
            if ppool[i][0] < plen:
                #We are in shorter prefixes, keep searching
                continue                
            elif (ppool[i][0] == plen):
                #We found the right length
                while (i<len(ppool)):
                    if prefix == ppool[i][1]:
                        grasp.tprint("Blocked insertion of duplicate prefix",
                                     prefstr(plen,prefix))
                        pool_lock.release()
                        return
                    if (prefix<ppool[i][1]) and (ppool[i][0] == plen) \
                       or (ppool[i][0] > plen):
                        #it belongs right here
                        ppool.insert(i,[plen,prefix])
                        pool_lock.release()
                        return
                    i += 1
            else:
                #We found a greater length
                ppool.insert(i,[plen,prefix])
                pool_lock.release()
                return
    #We didn't insert, so append
    ppool.append([plen,prefix])
    pool_lock.release()
    return

def insert4_pool(plen, prefix):
    """inserts IPv4-mapped prefix in pool in canonical order"""
    insert_pool(plen+96, prefix)


def sum_pool():
    """ -> estimate of IPv6 pool size in /'subnet_unit's"""
    spool = 0
    pool_lock.acquire()
    for i in range(len(ppool)):
        spool += 2**(subnet_unit-ppool[i][0])
    pool_lock.release()
    return spool

def sum4_pool():
    """ -> estimate of IPv4 pool size in /24s"""
    spool = 0
    pool_lock.acquire()
    for i in range(len(ppool)):
        if ppool[i][1][:12] == mappedpfx:
            spool += 2**(120-ppool[i][0])
    pool_lock.release()
    return spool    

def nudge_pool(l):
    """signal need for prefixes of length l"""
    global need
    need += 2**(subnet_length-l)
        
####################################
# Thread to compress pool
# Runs in background for ever
####################################

class compress(threading.Thread):
    """Thread to compress pool"""
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        while True:
            stopt = time.monotonic()+1 #Don't hold lock for >1s
            pool_lock.acquire()
            if len(ppool) > 1:
                #at least 2 entries
                l1 = ppool[0][0]
                p1 = ppool[0][1]
                for i in range(1,len(ppool)):
                    if time.monotonic()>stopt:
                        break
                    l2 = ppool[i][0]
                    p2 = ppool[i][1]
                    
                    if l1 == l2:
                        #same length, are p1 and p2 combinable?
                        #grasp.tprint(l1,ipaddress.IPv6Address(p1),l2,ipaddress.IPv6Address(p2))
                        if p1 == p2:
                            #this should never happen, but if it does
                            # we'll log it and delete the duplicate
                            grasp.tprint("Deleting duplicate prefix", prefstr(l2,p2))
                            del ppool[i]
                            break
                        nl = l1-1
                        np = mask_prefix(nl,p1)
                        if  np == mask_prefix(nl,p2):
                            #yes
                            del ppool[i]
                            del ppool[i-1]
                            pool_lock.release()
                            insert_pool(nl, np)
                            pool_lock.acquire()
                            break
                    #different length or no match, move on
                    l1 = l2
                    p1 = p2
            pool_lock.release()
            time.sleep(5)    
                
        

grasp.tprint("==========================")
grasp.tprint("ASA pfxm4 is starting up.")
grasp.tprint("==========================")
grasp.tprint("pfxm4 is a demonstration Autonomic Service Agent.")
grasp.tprint("It supports the IP Edge Prefix Management")
grasp.tprint("objective 'PrefixManagerT' and its companion")
grasp.tprint("'PrefixManager.Params', for IPv6 and IPv4.")
grasp.tprint("")
grasp.tprint("Supports draft-ietf-cbor-network-addresses rather")
grasp.tprint("than RFC 8992.")
grasp.tprint("As demonstration code it does not operate in real")
grasp.tprint("prefix-assigning nodes or perform real assignments.")
grasp.tprint("")
grasp.tprint("On Windows or Linux, after initialisation, there should")
grasp.tprint("be a nice window showing the negotiation process.")
grasp.tprint("==========================")

#grasp.test_mode = True # set if you want detailed diagnostics


####################################
# Set some control variables to default values
####################################

origin = False
subnet_default = 64
subnet_max = 96
subnet_min = 48
subnet_length = subnet_default

####################################
# Input mode etc. from user
# If origin, create initial pool
####################################

print("Startup dialogue: press Enter for defaults")

try:
    _ = input("Act as origin? Y/N:")
    if _[0] == "Y" or _[0] =="y":
        origin = True
except:
    pass

if origin:
    grasp.tprint("This ASA will provide an initial prefix pool.")
    grasp.tprint("Also, it will supply default parameters for other ASAs.")
    try:
        _ = input("Enter longest allowed IPv6 subnet request:")
        subnet_length = int(eval(_))
    except:
        pass
    if subnet_length > subnet_max:
        subnet_length = subnet_max
    if subnet_length < subnet_min:
        subnet_length = subnet_min
    grasp.tprint("Using allowed IPv6 subnet length", subnet_length)
    subnet_unit = subnet_default #origin always counts in default size
    create_pool()
    dump_pool()
    btext = "Pfxm4 Origin"

else:
    grasp.tprint("This ASA will start with an empty prefix pool.")
    try:
        _ = input("Enter subnet length to be delegated:")
        subnet_length = int(eval(_))
    except:
        pass
    if subnet_length > subnet_max:
        subnet_length = subnet_max
    if subnet_length < subnet_min:
        subnet_length = subnet_min
    grasp.tprint("Using subnet length", subnet_length)
    subnet_unit = subnet_length #delegator counts in delegated lengths
    quickly = False
    try:
        _ = input("Run delegation extra fast? Y/N:")
        if _[0] == "Y" or _[0] =="y":
            quickly = True
    except:
        pass
    btext = "Pfxm4 Delegator"

####################################
# Register ASA/objectives
####################################

_err,asa_nonce = grasp.register_asa("pfxm4")
if not _err:
    grasp.tprint("ASA pfxm4 registered OK")

else:
    grasp.tprint("Fatal error:", grasp.etext[_err])
    exit()
    
obj1 = grasp.objective("PrefixManagerT")
obj1.loop_count = 4
obj1.neg = True
obj1.value = None

# Value is defined as CBOR Tag 52 or 54 (prefix first versions)

ipv = 0
PD = ipv #not used in this version
lgth = PD+1
pfx = lgth+1

_err = grasp.register_obj(asa_nonce,obj1)
if not _err:
    grasp.tprint("Objective", obj1.name, "registered OK")
else:
    grasp.tprint("Fatal error:", grasp.etext[_err])
    exit()

obj2 = grasp.objective("PrefixManager.Params")
obj2.loop_count = 4
obj2.synch = True

if origin:
    _err = grasp.register_obj(asa_nonce,obj2)
    if not _err:
        grasp.tprint("Objective", obj2.name, "registered OK")
    else:
        grasp.tprint("Fatal error:", grasp.etext[_err])
        exit()

####################################
# Start pretty printing
####################################

grasp.init_bubble_text(btext)

####################################
# If we have an initial pool, start
# acting as a source of parameters by
# flooding and listening for synch requests
####################################

if origin:
    # Arbitrary parameter values for demo only
    obj2.value =  [[["role", "RSG"],["prefix_length", 34]],
                   [["role", "ASG"],["prefix_length", 44]],
                   [["role", "CSG"],["prefix_length", 56]]]




##  Or they could be:
##  Turning the alists into maps:
##
##    obj2.value = [{"role": "RSG", "prefix_length": 34},
##                  {"role": "ASG", "prefix_length": 44},
##                  {"role": "CSG", "prefix_length": 56}]
##
##  If "role" really is the "key" here, this could then turn into:
##
##    obj2.value =  {"RSG": {"prefix_length": 34},
##                   "ASG": {"prefix_length": 44},
##                   "CSG": {"prefix_length": 56}}
##  Grüße, Carsten
##
##  or from original draft:
##    
##    obj2.value =       [
##         {"role": [{"role_name": "RSG"},
##            {"role_characteristic":
##               [{"prefix_length": "34"}]}
##            ]},
##         {"role": [{"role_name": "ASG"},
##            {"role_characteristic":
##               [{"prefix_length": "44"}]}
##            ]},
##         {"role": [{"role_name": "CSG"},
##            {"role_characteristic":
##               [{"prefix_length": "56"}]}
##            ]}
##      ]    

    flooder().start()
    grasp.tprint("Flooding", obj2.name, "for ever")

    _err = grasp.listen_synchronize(asa_nonce, obj2)
    if not _err:
        grasp.tprint("Listening for synch requests for", obj2.name)
    else:
        grasp.tprint("Error in listen_synchronize:", grasp.etext[_err])

##dump_some()

##while True: # break point for debugging initial logic
##    time.sleep(5)

###################################
# Negotiate obj1 as listener for ever
# unless pool is empty
###################################

main_negotiator().start()

###################################
# Get parameters (if not origin)
###################################

if not origin:
    grasp.tprint("Attempting to obtain prefix management parameters")
    err, param_obj = grasp.synchronize(asa_nonce, obj2, None, 3000)
    if not err:
        grasp.tprint("Results for", param_obj.name,":", param_obj.value)
    else:
        grasp.tprint("Error obtaining parameters:", grasp.etext[err])
        
    need = 32 #arbitrary starter pack
    delegator().start()

###################################
# Start garbage collector
###################################

compress().start()

###################################
# Negotiate obj1 as requester for ever
# whenever pool is low
###################################

want_obj = grasp.objective("PrefixManagerT")
want_obj.neg = True

good_peer = None # where we remember a helpful peer ASA
next_peer = 0    # for cycling through peers
while True:
    #IPv6
    shortfall = need - sum_pool()
    if shortfall > 0:
        #find the next power of 2 above shortfall
        #and add 1 for luck
        if shortfall < 1:
            want_p = subnet_length - 1
        else:
            want_p = subnet_length - 2 - int(math.log(shortfall,2))
        grasp.tprint("IPv6 prefix pool is low, will ask for /"+str(want_p))
        #want_obj.value = [6, want_p, None]
        want_obj.value = build5254(6, grasp._unspec_address.packed, want_p)
        #want_obj.value = [6, False, want_p, None]
        #find a negotiation peer
        err, ll = grasp.discover(asa_nonce, want_obj, 1000, flush=True)
        if err:
            grasp.tprint("Discovery error:", grasp.etext[err])
        elif ll == []:
            grasp.tprint("No peer discovered")
            good_peer = None
        else:
            #pick a peer
            if len(ll) == 1:
                #only one choice
                peer = ll[0]
                grasp.tprint("Trying the only peer")
            elif good_peer in ll:
                #good one is still available
                peer = good_peer
                grasp.tprint("Trying previous peer")
            else:
##                #cycle through peers
##                if next_peer < len(ll):
##                    peer = ll[next_peer]
##                    next_peer += 1
##                else:
##                    peer = ll[0]
##                    next_peer = 1
                #pick peer at random
                next_peer = grasp._prng.randint(0,len(ll)-1)
                peer = ll[next_peer]
                grasp.tprint("Trying peer",next_peer,"out of",len(ll))
            err, snonce, answer = grasp.req_negotiate(asa_nonce, want_obj, peer, 3000)
            if not err:
                if snonce:
                    #we got an offer
                    vv, pp, ll = detag5254(answer.value)
                    if not vv:
                        #bad tag
                        grasp.end_negotiate(asa_nonce, snonce, False, "Bad tag "+str(ll))
                        grasp.tprint("Bad tag",ll)                      
                    elif ll < want_p +1:
                        #acceptable
                        grasp.end_negotiate(asa_nonce, snonce, True)
                        insert_pool(ll, pp)
                        need = 0
                        good_peer = peer #cache this one
                        grasp.tprint("Obtained", prefstr(ll,pp))
                    else:
                        #unacceptable
                        grasp.end_negotiate(asa_nonce, snonce, False, "Insufficient offer")
                        grasp.tprint("Refused prefix of length",ll)
            else:
                if err == grasp.errors.declined:
                    grasp.tprint("Peer declined:", answer)
                else:
                    grasp.tprint("req_negotiate error:", grasp.etext[err])

    #IPv4
    if sum4_pool() < 8:
        #want_obj.value = [4, 20, None]
        want_obj.value = build5254(4, ipaddress.IPv4Address('0.0.0.0').packed, 20)
        #want_obj.value = [4, False, 20, None]
        grasp.tprint("IPv4 prefix pool is low, will ask for /20")
        err, ll = grasp.discover(asa_nonce, want_obj, 1000, flush=True)
        if err:
            grasp.tprint("Discovery error:", grasp.etext[err])
        elif ll == []:
            grasp.tprint("No peer discovered")
            good_peer = None
        else:
            #pick a peer
            if len(ll) == 1:
                #only one choice
                peer = ll[0]
                grasp.tprint("Trying the only peer")
            else:
                #pick peer at random
                next_peer = grasp._prng.randint(0,len(ll)-1)
                peer = ll[next_peer]
                grasp.tprint("Trying peer",next_peer,"out of",len(ll))
            err, snonce, answer = grasp.req_negotiate(asa_nonce, want_obj, peer, 3000)
            if not err:
                if snonce:
                    #We got an offer. Since this is IPv4,
                    #we take anything we can get!
                    
                    vv, pp, ll = detag5254(answer.value)
                    if not vv:
                        grasp.end_negotiate(asa_nonce, snonce, False, "Bad tag "+str(ll))
                        grasp.tprint("Bad tag", ll)
                    else:
                        grasp.end_negotiate(asa_nonce, snonce, True)
                        insert4_pool(ll, mappedpfx+pp)
                        need = 0
                        good_peer = peer #cache this one
                        grasp.tprint("Obtained", pref4str(ll, pp))
            else:
                if err == grasp.errors.declined:
                    grasp.tprint("Peer declined:", answer)
                else:
                    grasp.tprint("req_negotiate error:", grasp.etext[err])


    #dump_pool()                
    grasp.tprint("IPv6 pool size", int(sum_pool()),"/"+str(subnet_unit)+"s")
    grasp.tprint("IPv4 pool size", sum4_pool(),"/24s")
    #dump_delegates()
    time.sleep(10)
    #dump_some()   
    
    
