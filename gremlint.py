
"""########################################################
########################################################
#                                                     
# GREMLIN: the GRASP daemon       
#                                                                            
# This module is for use in a node that can relay GRASP
# but is not running any ASA. This version needs no initial
# dialogue with the user. It runs in test mode to act
# as a monitor, without QUADs security.
#                                                     
# Because it's demonstration code written in an       
# interpreted language, performance is slow.          
#                                                     
# SECURITY WARNINGS:                                  
#  - assumes ACP up on all interfaces (or none)       
#  - assumes BUT DOES NOT CHECK that layer 2 is secured           
#  - does not watch for interface up/down changes
#    (but does handle IPv6 address changes)
#  - use of QUADS security is highly recommended
#                                                     
# LIMITATIONS:                                        
#  - only coded for IPv6, any IPv4 is accidental
#  - survival of address changes and CPU sleep/wakeup is patchy          
#  - workarounds for defects in Python socket module and
#    Windows socket peculiarities. Not tested on Android.
#
# Released under the BSD 2-Clause "Simplified" or "FreeBSD"
# License as follows:
#                                                     
# Copyright (C) 2019 Brian E. Carpenter.                  
# All rights reserved.
#
# Redistribution and use in source and binary forms, with
# or without modification, are permitted provided that the
# following conditions are met:
#
# 1. Redistributions of source code must retain the above
# copyright notice, this list of conditions and the following
# disclaimer.
#
# 2. Redistributions in binary form must reproduce the above
# copyright notice, this list of conditions and the following
# disclaimer in the documentation and/or other materials
# provided with the distribution.                                  
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS  
# AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED 
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A     
# PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
# THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
# USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)    
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
# IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING   
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
# USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE        
# POSSIBILITY OF SUCH DAMAGE.                         
#                                                     
########################################################
########################################################"""

import grasp
import time
print("Starting GRASP daemon without dialogue")
grasp.skip_dialogue(testing=True, selfing=True, quadsing=False, diagnosing=True)
grasp._initialise_grasp()
grasp.init_bubble_text("GRASP daemon")
grasp.tprint("Daemon running")
while True:
    time.sleep(60)

