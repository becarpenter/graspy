#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""This is an ASA whose purpose is to demonstrate MQTT
subscription in a GRASP/ACP environment.
It depends on flooded GRASP objective 'MQTT_broker' to
announce the address and port of the MQTT broker."""

# Released under the BSD "Revised" License.
# Some code borrowed from Antje Neve
#                                                     
# Copyright (C) 2026 Brian E. Carpenter.                  
# All rights reserved.

# 20261002 First version

import paho.mqtt.client as mqtt
import sys
import time
import socket
import json
sys.path.insert(0, '..') # in case graspi.py is one level up
import graspi

TOPIC = "GRASP/test"

ASA_name = "Subscriber" # Arbitrary ASA name, unique in the GRASP instance.

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

####################################
# Construct a GRASP objective and
# discover MQTT broker
####################################

broker_obj = graspi.objective("MQTT_broker")
broker_obj.synch = True

while True:  
    err, results = graspi.get_flood(asa_handle, broker_obj)
    if (not err) and len(results):
        # results contains the returned locators if any
        # Pick the first one (lazy code)
        x = results[0]                  
        graspi.tprint("Got", broker_obj.name, "at",
                     x.source.locator, x.source.protocol, x.source.port)
        new_broker = x
        break
    else:
        if err:
            graspi.tprint("get_flood failed", graspi.etext[err])
    time.sleep(60)

BROKER = str(new_broker.source.locator)
PORT = new_broker.source.port
if new_broker.source.protocol != socket.IPPROTO_TCP:
    graspi.tprint("Wrong protocol")
    sys.exit()
    
####################################
# Define MQTT callbacks and environment
####################################

def on_connect(client, userdata, flags, reason_code, properties):
    graspi.tprint("Connect:", reason_code)
    client.subscribe(TOPIC, qos=1)

def on_subscribe(client, userdata, mid, reason_codes, properties):
    graspi.tprint("Subscription confirmed:", reason_codes)

def on_message(client, userdata, message):
    graspi.tprint("Message on", message.topic, ":", json.loads(message.payload.decode("utf-8")))
    #print("QoS:", message.qos)
    #if message.properties:
    #    graspi.tprint("Properties:", message.properties)

client = mqtt.Client(
    callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
    client_id="GRASP-subscriber1",
    protocol=mqtt.MQTTv5,
)

client.on_connect = on_connect
client.on_subscribe = on_subscribe
client.on_message = on_message

######################
# Subscribe for ever
######################

client.connect(BROKER, PORT, keepalive=60)
client.loop_forever()
