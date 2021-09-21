#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""########################################################
########################################################
# GRASPconfig is an experimental Autonomic Service Agent.
# It supports the proposed GRASP objective GraspConfig
# in order to distribute GRASP configuration information
# throughout an autonomic network.
#
# It acquires configuration data periodically from
# file "graspconfig.json".
#
# See grasp.py for license, copyright, and disclaimer.
#
########################################################"""

import graspi
import time
import json

###################################
# JSON file format is like:
#
# {"sender_loop_count": 15,
#  "grasp_version": 1,
#  "max_multicast": 8192,
#  "max_unicast": 5000,
# }
###################################

###################################
# Constants for building dictionary
###################################

class codepoints:
    """Code points for configuration dictionary"""
    def __init__(self):
        self.sender = 0
        self.sender_loop_count = 1
        self.grasp_version = 2
        self.max_multicast = 3
        self.max_unicast = 4
        self.test_only = 999
        
cp = codepoints()

####################################
# Utility function to convert
# config name to codepoint
####################################

cpdict = cp.__dict__

def cpt(jname):
    if jname in cpdict:
        return cpdict[jname]
    else:
        raise Exception("Invalid configuration element")


####################################
# Utility function to create a
# skeleton flood element
####################################

def new_felement():
    """-> default flood element"""
    return {cp.sender: graspi.grasp._session_locator.packed,
            cp.sender_loop_count: 15, # Autonomic network with >15 hops is unlikely
            cp.grasp_version: 1,
            cp.max_multicast: graspi.grasp.GRASP_DEF_MAX_SIZE,
            cp.max_unicast: graspi.grasp.GRASP_DEF_MAX_SIZE,
            }
        



graspi.tprint("==========================")
graspi.tprint("ASA GRASPconfig is starting up.")
graspi.tprint("==========================")
graspi.tprint("GRASPconfig is an experimental Autonomic Service Agent.")
graspi.tprint("It runs indefinitely to flood GRASP configuration")
graspi.tprint("data to all GRASP nodes in the autonomic network.")
graspi.tprint("On Windows or Linux, there should be a nice")
graspi.tprint("window that displays the process.")
graspi.tprint("==========================")

####################################
# General initialisation
####################################

time.sleep(5) # so the user can read the text

graspi.skip_dialogue(testing="ask", selfing=True, diagnosing=True)

####################################
# Register ASA/objective
####################################

err,asa_handle = graspi.register_asa("GRASPconfig")
if not err:
    graspi.tprint("ASA GRASPconfig registered OK")
else:
    graspi.tprint("ASA GRASPconfig registration error:", graspi.etext[err])
    exit()
    
obj1 = graspi.objective("GraspConfig")
obj1.synch = True

err = graspi.register_obj(asa_handle,obj1)
if not err:
    graspi.tprint("Objective", obj1.name, "registered OK")
else:
    graspi.tprint("Objective", obj1.name, "registration error:",
                  graspi.etext[err])
    exit()

####################################
# Initialise objective
####################################


obj1.value = new_felement()
obj1.loop_count = obj1.value[cp.sender_loop_count]


###################################
# Set up pretty printing
###################################

graspi.init_bubble_text("GRASPconfig")
graspi.tprint("GRASPconfig is flooding")

###################################
# Fetch config source and
# flood objective for ever
###################################

while True:
    try:
        #Read JSON file as Python object
        f = open("graspconf.json","r")
        jconf = json.load(f)
        f.close()

        #Update objective according to JSON content
        for el in jconf:
            k, v = el, jconf[el]
            obj1.value[cpt(k)] = v

    except Exception as ex:
        graspi.tprint("Could not acquire or process configuration file:", ex)
        time.sleep(120)
        continue       
    
    err = graspi.flood(asa_handle, 120000, [graspi.tagged_objective(obj1,None)])
    if err:
        graspi.tprint("Flood error:",graspi.etext[err])
    time.sleep(60)

    



