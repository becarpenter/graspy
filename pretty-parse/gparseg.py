"""########################################################
########################################################
#                                                     
# GPARSEG: the GRASP pcapng pretty parser       
#                                                                            
# This module can parse a CBOR-encoded GRASP trace and
# pretty print the result. It reuses the main grasp.py
# definitions and parser.
#
# Needs grasp.py and its dependencies in the PYTHON path
# Needs cbor2, dpkt and python-pcapng (NOT plain pcapng)
#
# See grasp.py for license, copyright, and disclaimer.                        
#                                                     
########################################################
########################################################"""

import grasp
#and now get some GRASP stuff into our namespace for convenience
from grasp import *
from grasp import _parse_msg, _mess_check

import cbor2 as cbor
import ipaddress
import pprint
try:
    from pcapng import FileScanner
except:
    raise Exception("Install python-pcapng (NOT plain pcapng) with pip or apt-get")
import dpkt
from tkinter import Tk
from tkinter.messagebox import showinfo
from tkinter.filedialog import askopenfilename

# We will not initialise GRASP, but we set a flag to print parsing error messages:

grasp._mess_check = True

# Override GRASP thread-safe printing (a "monkey patch")

def tprint(*whatever):
    print(ttt, end="", flush=False)
    print(*whatever)
grasp.tprint = tprint

# Map of GRASP protocol constant names

gc = {M_NOOP: 'M_NOOP',
M_DISCOVERY: 'M_DISCOVERY', 
M_RESPONSE: 'M_RESPONSE',
M_REQ_NEG: 'M_REQ_NEG',
M_REQ_SYN: 'M_REQ_SYN',
M_NEGOTIATE: 'M_NEGOTIATE',
M_END: 'M_END',
M_WAIT: 'M_WAIT',
M_SYNCH: 'M_SYNCH',
M_FLOOD: 'M_FLOOD',
M_INVALID: 'M_INVALID',

O_DIVERT: 'O_DIVERT',
O_ACCEPT: 'O_ACCEPT',
O_DECLINE: 'O_DECLINE',
O_IPv6_LOCATOR: 'O_IPv6_LOCATOR',
O_IPv4_LOCATOR: 'O_IPv4_LOCATOR',
O_FQDN_LOCATOR: 'O_FQDN_LOCATOR',
O_URI_LOCATOR: 'O_URI_LOCATOR'
 }

#
M_s = (M_NOOP,
M_DISCOVERY, 
M_RESPONSE,
M_REQ_NEG,
M_REQ_SYN,
M_NEGOTIATE,
M_END,
M_WAIT,
M_SYNCH,
M_FLOOD,
M_INVALID)

class pay:
    """A preprocessed payload"""
    def __init__(self, payload, source, dest):
        self.payload = payload
        self.source = source
        self.dest = dest

#Pretty printer for generic Python object
pp = pprint.PrettyPrinter(indent=4)


def obprint(obj):
    """Pretty print a GRASP objective"""
    if not obj:
        return
    if not obj.name:
        obj.name = "VOID NAME!"    
    tprint("Objective:", obj.name)
    tab()
    flags = ""
    if obj.discoverable:
        flags += "|Discoverable"
    if obj.neg:
        flags += "|Negotiable"
    if obj.dry:
        flags += "|Dry Run"
    if obj.synch:
        flags += "|Synchronizable"
    if flags:
        tprint("Flags:", flags)
    else:
        tprint("Warning: no flags")
    tprint("Loop count:", obj.loop_count)
    tprint("Value:", obj.value)
    untab()

def opprint(opt):
    """Pretty print a GRASP option"""
    if not opt:
        return
    tprint("Option:", opt.otype, '=', gc[opt.otype])
    if opt.otype in (O_IPv6_LOCATOR,O_IPv4_LOCATOR,O_FQDN_LOCATOR,O_URI_LOCATOR):
        tab()
        loprint(opt)
        untab()
    elif opt.otype == O_DIVERT:
        tab()
        for op in opt.embedded:
            opprint(op)
        untab()
    elif opt.otype == O_ACCEPT:
        pass #no contents
    elif opt.otype == O_DECLINE:
        if opt.reason:
            tab()
            tprint("Reason:", opt.reason)
            untab()
    else:
        raise Exception("Unknown option") # Really should never get here...


def loprint(loco):
    """Pretty print a GRASP locator option"""
    if loco.otype in (O_IPv6_LOCATOR, O_IPv4_LOCATOR):
        tprint("Locator:", ipaddress.ip_address(loco.locator))
    elif loco.otype in (O_FQDN_LOCATOR, O_URI_LOCATOR):
        tprint(gc[loco.otype]+":", loco.locator)
    tab()
    tprint("Protocol:", loco.protocol)
    tprint("Port:", loco.port)
    untab()

ttt = ""  # initial indentation level

def tab():
    """Indent pretty printing"""
    global ttt
    ttt += "    "
    
def untab():
    """Unindent pretty printing"""
    global ttt
    ttt = ttt[:-4]

def play(new):
    """Add player if new"""
    global players
    if not new in players:
        players.append(new)

players = []

Tk().withdraw() # we don't want a full GUI
T = "GRASP pcapng analyzer"
showinfo(title=T,
         message = "I require a pcapng file containing GRASP traffic.")

fn = (askopenfilename(title="Select input file", defaultextension=".pcapng"))
f=open(fn,'rb')
s=FileScanner(f)
tprint("Using file", fn)
trace = []
for b in s:
    try:
        trace.append(b.packet_data)
    except:
        pass
    
#Now we have raw packets

#Zeroth pass to exclude everything that isn't IPv6,

for i in range(len(trace)):
    record = trace[i]
    packet = dpkt.ethernet.Ethernet(record).data
    if not tname(packet) == "IP6":
        trace[i] = None        

#First pass to catch all GRASP multicasts
for i in range(len(trace)):
    try:
        record = trace[i]
        if not record:
            continue
        packet = dpkt.ethernet.Ethernet(record).data
        source = ipaddress.IPv6Address(packet.src)
        dest = ipaddress.IPv6Address(packet.dst)
        payload = packet.data
        if tname(payload) == "UDP":
            if payload.dport == 7017:
                #Assume M_DISCOVERY or M_FLOOD
                #print("GRASP multicast from", source)
                play(source)
                #extract the GRASP payload and parse it
                msg = _parse_msg(cbor.loads(payload.data))
                if msg.mtype in (M_DISCOVERY, M_FLOOD):
                    play(ipaddress.IPv6Address(msg.id_source))
                if msg.flood_list:
                    for fo in msg.flood_list:
                        if fo.loco and fo.loco.otype == O_IPv6_LOCATOR:
                            play(ipaddress.IPv6Address(fo.loco.locator))
            else:
                #some other UDP
                trace[i] = None
    except:
        trace[i] = None #remove invalid packets                          

#Second pass to catch M_RESPONSEs
        
for i in range(len(trace)):
    try:
        record = trace[i]
        if not record:
            continue
        packet = dpkt.ethernet.Ethernet(record).data
        source = ipaddress.IPv6Address(packet.src)
        dest = ipaddress.IPv6Address(packet.dst)
        payload = packet.data
        if tname(payload) == "TCP":
            if source in players and dest in players:
                #candidate for M_RESPONSE
                #(if it isn't valid CBOR or doesn't look like M_RESPONSE,
                #we'll throw an exception)
                #extract the potential GRASP payload and parse it
                msg = _parse_msg(cbor.loads(payload.data))
                if msg.mtype == M_RESPONSE:
                    play(ipaddress.IPv6Address(msg.id_source))
                    for opt in msg.options:
                        if opt.otype == O_IPv6_LOCATOR:
                            play(ipaddress.IPv6Address(opt.locator))
                        elif opt.otype == O_DIVERT:
                            for loco in opt.embedded:
                                if loco.otype  == O_IPv6_LOCATOR:
                                    play(ipaddress.IPv6Address(loco.locator))
    except:
        trace[i] = None #remove invalid packets

#Third pass to catch any other GRASP TCP
        
for i in range(len(trace)):
    try:
        record = trace[i]
        if not record:
            continue
        packet = dpkt.ethernet.Ethernet(record).data
        source = ipaddress.IPv6Address(packet.src)
        dest = ipaddress.IPv6Address(packet.dst)
        payload = packet.data
        if tname(payload) == "TCP":
            if source in players or dest in players:
                #candidate for GRASP unicast
                #(if it isn't valid CBOR or doesn't look like GRASP,
                #we'll throw an exception)
                #extract the potential GRASP payload and parse it
                if not cbor.loads(payload.data)[0] in M_s:
                    trace[i] = None #whatever it is, it isn't GRASP
                else:
                    #looks like GRASP, maybe add a player
                    play(source)
                    play(dest)                
            else:
                #not a GRASP candidate
                trace[i] = None
    except:
        trace[i] = None #remove invalid packets

#Finally reduce trace to (probable) raw GRASP packets + addresses

for i in range(len(trace)):
    record = trace[i]
    if record:
        packet = dpkt.ethernet.Ethernet(record).data
        payload = packet.data
        source = ipaddress.IPv6Address(packet.src)
        dest = ipaddress.IPv6Address(packet.dst)
        if tname(payload) in ("UDP", "TCP"):
            trace[i] = pay(payload.data, source, dest)
        else:
            trace[i] = None                      

print("\nProbable GRASP Players:\n")
for p in players:
    print(str(p))
tprint("\nGRASP Trace:")

### Chop it down for debugging
##trace = trace[:100]


# Main loop

for raw in trace:
    if not raw:
        continue
    
    tprint("")
    tprint(str(raw.source), "==>", str(raw.dest))
    
    try:
        payload = cbor.loads(raw.payload)
    except Exception as ex:
        tprint("CBOR decode error:", ex)
        continue
    msg = _parse_msg(payload)
    if not msg:
         tprint("Parsing failed: raw decode:")
         pp.pprint(payload)
         continue

    tprint("Message type:", msg.mtype, "=", gc[msg.mtype])
    tprint("Session ID:", msg.id_value)

    if msg.mtype == M_DISCOVERY:
        tprint("IPv6 Initiator:", ipaddress.IPv6Address(msg.id_source))
        tab()
        obprint(msg.obj)
        untab()

    elif msg.mtype == M_RESPONSE:
        tprint("IPv6 Initiator:", ipaddress.IPv6Address(msg.id_source))
        tprint("TTL:", msg.ttl)
        tab()
        for op in msg.options:
            opprint(op)
        untab()
        obprint(msg.obj)

    elif msg.mtype in (M_REQ_SYN, M_SYNCH, M_REQ_NEG, M_NEGOTIATE):
        obprint(msg.obj)

    elif msg.mtype == M_END:
        tab()
        for op in msg.options:
            opprint(op)
        untab()

    elif msg.mtype == M_WAIT:
        tprint("TTL extension:", msg.ttl)

    elif msg.mtype == M_INVALID:
        tprint("Reason:", msg.content)        

    elif msg.mtype == M_FLOOD:
        tprint("IPv6 Initiator:", ipaddress.IPv6Address(msg.id_source))
        if msg.flood_list:
            tprint("TTL:", msg.ttl)
            tprint("Flood list length:", len(msg.flood_list))
            tab()
            for fo in msg.flood_list:
                obprint(fo.obj)
                opprint(fo.loco)
            untab()
        else:
            tprint("No flood list!")

    


