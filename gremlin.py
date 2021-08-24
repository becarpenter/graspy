
"""########################################################
########################################################
#                                                     
# GREMLIN: the GRASP daemon       
#                                                                            
# This module is for use in a node that can relay GRASP
# but is not running any ASA
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

import grasp
import time
print("Starting GRASP daemon")
grasp._initialise_grasp()
grasp.init_bubble_text("GRASP daemon")
grasp.tprint("Daemon running")
while True:
    time.sleep(60)
