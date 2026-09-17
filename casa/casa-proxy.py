#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""This is a proof-of-concept BRSKI proxy for the CASA suite.
It finds a BRSKI registrar and advertises itself by flooding
to on-link pledges seeking a proxy, using GRASP per RFC8995.
It then proxies the BRSKI HTTPS/TLS/TCP transactions.
"""

# Released under the BSD "Revised" License.
#                                                     
# Copyright (C) 2026 Brian E. Carpenter.                  
# All rights reserved.

# 20260902 First version
# 20260912 Updated misleading comment
# 20260917 Label window

import sys
sys.path.insert(0, '..') # in case graspi.py is one level up
import os
import graspi
import time
import socket
import ipaddress
import threading

###################################
# TCP proxy support
# Adapted from code suggested by Google AI.
###################################

def handle_client(client_socket, remote_host, remote_port):
    # Connect to the remote target server
    remote_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    try:
        remote_socket.connect((remote_host, remote_port))
    except Exception as e:
        graspi.tprint(f"Failed to connect to remote host: {e}")
        client_socket.close()
        return

    # Start threads to transfer data in both directions simultaneously
    done = 0  #shared between directions
    done_lock = threading.Lock()
    client_to_remote = threading.Thread(
        target=forward_stream, 
        args=(client_socket, remote_socket, "Client -> Remote", done, done_lock)
    )
    remote_to_client = threading.Thread(
        target=forward_stream, 
        args=(remote_socket, client_socket, "Remote -> Client", done, done_lock)
    )

    client_to_remote.start()
    remote_to_client.start()

def forward_stream(source, destination, direction, done, done_lock):
    try:
        while True:
            # Receive data chunk from source
            data = source.recv(4096)
            if not data:
                time.sleep(2)       # don't close down too soon
                with done_lock:
                    done += 1       # += is not thread safe
                while not done == 2:
                    time.sleep(1)   # don't close down alone
                break
            
##            # Print a brief log statement
##            # (for unknown reasons, graspi.tprint() fails here)
##            print(f"[{direction}] Forwarding {len(data)} bytes")
            
            # Forward data to destination
            destination.sendall(data)
    except Exception as e:
        pass
    finally:
        # Safely shut down sockets when the connection drops
        try:
            source.close()
        except: pass
        try:
            destination.close()
        except: pass

def start_proxy(local_host, local_port, local_zone, remote_host, remote_port):
    global stash
    # Initialize the server socket to listen for incoming connections
    server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    stash.append(server)
    try:
        server.bind((local_host, local_port, 0, local_zone))
    except Exception as e:
        graspi.tprint(f"Failed to bind to {local_host}%{local_zone}:{local_port} - {e}")
        return(False)
        
    server.listen(5)
    graspi.tprint(f"Proxy listening on {local_host}%{local_zone}:{local_port}")
    graspi.tprint(f"Forwarding traffic to {remote_host}:{remote_port}")

    while registrar_ok:
        try:
            client_socket, addr = server.accept()
            graspi.tprint(f"Accepted connection from {addr[0]}:{addr[1]}")
            
            # Create a thread to handle the active connection
            proxy_thread = threading.Thread(
                target=handle_client, 
                args=(client_socket, remote_host, remote_port)
            )
            proxy_thread.start()
        except:
            # socket closed by kill_proxies()
            pass
    return(True)

def flood_out():
    """Flood out proxy's GRASP objective"""
    global registrar
    if not registrar:
        return(False)
    r_addr = registrar.locator
    r_port = registrar.port
    r_proto = registrar.protocol
    graspi.tprint("Chose registrar", r_addr, r_proto, r_port)

    proxy_locator.protocol = registrar.protocol
    if registrar.protocol == socket.IPPROTO_TCP:            
        proxy_locator.port = t_port
    elif registrar.protocol == socket.IPPROTO_UDP:        
        proxy_locator.port = u_port
    elif registrar.protocol == socket.IPPROTO_IPV6:
        proxy_locator.port = 0
    else:
        return(False) # unknown method
    
    graspi.tprint("Flooding",proxy_obj.name, proxy_locator.locator, proxy_locator.protocol, proxy_locator.port)
    graspi.flood(_asa_nonce, proxy_ttl, graspi.tagged_objective(proxy_obj, proxy_locator))
    return(True)

class launch_proxy(threading.Thread):
    """Thread to launch a TCP proxy"""
    def __init__(self, local_host, local_port, local_zone, remote_host, remote_port):
        threading.Thread.__init__(self)
        self.lh = local_host
        self.lp = local_port
        self.lz = local_zone
        self.rh = remote_host
        self.rp = remote_port
        
    def run(self):
        start_proxy(self.lh, self.lp, self.lz, self.rh, self.rp)


def launch_proxies(registrar):
    """Launch a TCP proxy on each interface"""
    global registrar_ok
    registrar_ok = True
    for x in graspi.grasp._ll_zone_ids:
        launch_proxy(str(x[1]), t_port, x[0], str(registrar.locator), registrar.port).start()
    

def kill_proxies(msg):
    """Kill active TCP proxies"""
    global registrar_ok
    registrar_ok = False
    for s in stash:
        s.close()
        stash.remove(s)
    graspi.tprint("Registrar ", msg)

###################################
# Main thread starts here
###################################

if not "idlelib" in sys.modules:
    sys.stdout.write(f"\x1b]2;{"CASA proxy"}\x07") #Label window
    sys.stdout.flush()

# Note: silent=True would suppress all GRASP printing
graspi.skip_dialogue(selfing=True, be_dull=True, figging=False) #, silent=True)

graspi.tprint("CASA proxy is starting up.")

####################################
# Register this ASA
####################################

# The ASA name is arbitrary - it just needs to be
# unique in the GRASP instance.

_err,_asa_nonce = graspi.register_asa("CASA-proxy")
if not _err:
    graspi.tprint("ASA CASA-proxy registered OK")
else:
    graspi.tprint("ASA registration failure:",graspi.etext[_err])
    exit()

####################################
# Construct a GRASP objective
####################################

# This is an empty GRASP objective to find the registrar
# It's only used for get_flood so doesn't need to be filled in

reg_obj = graspi.objective("AN_join_registrar")
reg_obj.synch = True

####################################
# Create port for the proxy's communication
# with pledges
####################################

t_port = 11800  # For this PoC, we just make up a number

u_port = t_port # never used in CASA suite, kept for completeness

proxy_address = ipaddress.IPv6Address('::') # This is the unspecified address,
                                     # which signals link-local address to API
proxy_ttl = 180000 # milliseconds to live of the announcement

stash =[]   # where we stash active TCP proxy listening sockets

####################################
# Construct a correponding asa_locator
####################################

proxy_locator = graspi.asa_locator(proxy_address,0,False)
proxy_locator.is_ipaddress = True


####################################
# Construct the GRASP objective to announce the proxy
####################################

proxy_obj = graspi.objective("AN_proxy")
proxy_obj.synch = True
proxy_obj.value = ""
# proxy_obj.loop_count not set, the API forces it to 1 for link-local use


####################################
# Register the GRASP objective
####################################

_err = graspi.register_obj(_asa_nonce, proxy_obj)
if not _err:
    graspi.tprint("Objective", proxy_obj.name,"registered OK")
else:
    graspi.tprint("Objective registration failure:", graspi.etext[_err])
    exit() # code doesn't handle registration errors
    
graspi.tprint("Proxy ASA starting now")

###################################
# Now find a registrar
###################################

registrar_ok = False
registrar = None
while True:  
    err, results = graspi.get_flood(_asa_nonce, reg_obj)
    if (not err) and len(results):
        # results contains the returned locators if any
        # Pick the first one (lazy code)
        x = results[0]                  
        graspi.tprint("Got", reg_obj.name, "at",
                     x.source.locator, x.source.protocol, x.source.port)
        new = x.source
    else:
        if err:
            graspi.tprint("get_flood failed", graspi.etext[_err])
        new = None

    if registrar and not new:
        # we lost the registrar
        registrar = None
        kill_proxies("lost")
    elif registrar and new:
        if (registrar.locator != new.locator) or (registrar.port != new.port):
            # change of registrar
            kill_proxies("change") 
            registrar = new 
            launch_proxies(registrar)   # launch proxies
        else:
            graspi.tprint("Registrar stable")
    elif not registrar and new:
        # new registrar found
        registrar = new
        launch_proxies(registrar)   # launch proxies
    elif not registrar and not new:
        graspi.tprint("Waiting for registrar")

    flood_out()     # flood proxy objective if registrar found
    time.sleep(30)  # arbitrary wait 
