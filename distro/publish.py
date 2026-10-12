#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""This is an ASA whose purpose is to demonstrate objective
publication in a GRASP/ACP environment.
"""

# Released under the BSD "Revised" License.
#                                                     
# Copyright (C) 2026 Brian E. Carpenter.                  
# All rights reserved.

# 20261008 First version

import sys
import threading
import time
import socket
import json
#sys.path.insert(0, '..') # in case graspi.py is one level up
import graspi

ASA_name = "publish" # Arbitrary ASA name, unique in the GRASP instance.

###################################
# Main thread starts here
###################################

if not "idlelib" in sys.modules:
    sys.stdout.write("\x1b]2;"+ASA_name+"\x07") #Label window
    sys.stdout.flush()

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
    sys.exit()

time.sleep(10) # wait until GRASP kernel is sure to be ready



####################################
# Flood something
####################################

flob = graspi.objective("example.org:Sub/Intent/VoIPQoS")
flob.synch = True
flob.loop_count = 6
voip_dict = {
  "intent": {
    "name": "high-priority-voice",
    "target_scope": {
      "device_group": "branch-routers",
      "interface": "GigabitEthernet0/1"
    },
    "objective": {
      "service_type": "QoS",
      "action": "enforce",
      "parameters": {
        "bandwidth_percent": 30,
        "priority": "high",
        "latency_max_ms": 15
      }
    }
  }
}
flob.value = json.dumps(voip_dict)
flob_address = graspi.grasp._my_address
flob_locator = graspi.asa_locator(flob_address,0,False)
flob_locator.is_ipaddress = True
_err = graspi.register_obj(asa_handle, flob)
if not _err:
    graspi.tprint("Objective", flob.name,"registered OK")
else:
    graspi.tprint("Objective registration failure:", graspi.etext[_err])
    sys.exit() # code doesn't handle registration errors
    
while True:
    graspi.tprint("Flooding",flob.name, flob_locator.locator)
    graspi.flood(asa_handle, 0, graspi.tagged_objective(flob, flob_locator))
    time.sleep(30)  # arbitrary wait
