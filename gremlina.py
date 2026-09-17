#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""This is a GRASP daemon, intended to run indefinitely in
a GRASP node with several interfaces, to perform GRASP relaying.
No dialogue.
"""

# Released under the BSD "Revised" License.
#                                                     
# Copyright (C) 2026 Brian E. Carpenter.                  
# All rights reserved.

import graspi  #needs to be in python path
import time
import sys
# Start GRASP daemon without dialogue
graspi.skip_dialogue(selfing=True, figging=False, silent=True)
graspi.grasp._initialise_grasp()
print("GRASP daemon running")
if not "idlelib" in sys.modules:
    sys.stdout.write(f"\x1b]2;{"GRASP daemon"}\x07") #Label window
    sys.stdout.flush()

while True:
    time.sleep(60)

