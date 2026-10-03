#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""This is an ASA whose purpose is to announce an MQTT broker
via GRASP for all ACP nodes.
In the real world it would either also contain the broker code
or launch it independently. This version simply checks whether
its Windows host already runs the Mosquitto.org broker"""

# Released under the BSD "Revised" License.
#                                                     
# Copyright (C) 2026 Brian E. Carpenter.                  
# All rights reserved.

# 20261002 First version

import sys
sys.path.insert(0, '..') # in case graspi.py is one level up
import os
import subprocess
import graspi
import time
import socket
import ipaddress
import threading

MQTT_PORT = 1883  # per IANA

ASA_name = "Broker announce" # Arbitrary ASA name, unique in the GRASP instance.

def running():
    """Is mosquitto running?"""
    cmd='tasklist /FI "imagename eq mosquitto.exe"'
    do_cmd = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = do_cmd.communicate()
    if out and 'mosquitto.exe' in out.decode('utf-8'):
        return(True)

###################################
# Main thread starts here
###################################

if not "idlelib" in sys.modules:
    sys.stdout.write("\x1b]2;"+ASA_name+"\x07") #Label window
    sys.stdout.flush()
if not os.name=="nt":
    print("This ASA only works on Windows - cannot continue!")
    time.sleep(10)
    sys.exit()
if not running():
    print("mosquitto is not running - cannot continue!")
    time.sleep(10)
    sys.exit()            

# Note: silent=True would suppress all GRASP printing
graspi.skip_dialogue(selfing=True, figging=False) #, silent=True)

graspi.tprint(ASA_name, "is starting up.")

####################################
# Register this ASA
####################################

err, asa_handle = graspi.register_asa(ASA_name)
if not err:
    graspi.tprint(ASA_name, "registered OK")
else:
    graspi.tprint("ASA registration failure:",graspi.etext[err])
    sys.exit() # code doesn't handle registration errors


####################################
# Construct the GRASP objective and
# locator to announce the broker
####################################

broker_obj = graspi.objective("MQTT_broker")
broker_obj.synch = True
broker_obj.value = ""
broker_obj.loop_count = 6  # limit multicast radius

broker_address = graspi.grasp._my_address # not exactly an act of faith
broker_ttl = 180000 # milliseconds to live of the announcement

broker_locator = graspi.asa_locator(broker_address,0,False)
broker_locator.is_ipaddress = True
broker_locator.protocol = socket.IPPROTO_TCP
broker_locator.port = MQTT_PORT

####################################
# Register the GRASP objective
####################################

_err = graspi.register_obj(asa_handle, broker_obj)
if not _err:
    graspi.tprint("Objective", broker_obj.name,"registered OK")
else:
    graspi.tprint("Objective registration failure:", graspi.etext[_err])
    sys.exit() # code doesn't handle registration errors
    
graspi.tprint("Broker announce flood starting now")
graspi.tprint("Flooding",broker_obj.name, broker_locator.locator, broker_locator.protocol, broker_locator.port)

while True:  
    graspi.flood(asa_handle, broker_ttl, graspi.tagged_objective(broker_obj, broker_locator))
    time.sleep(30)  # arbitrary wait 
