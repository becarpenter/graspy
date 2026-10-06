#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""This is an ASA whose purpose is to demonstrate MQTT
publication in a GRASP/ACP environment.
It depends on flooded GRASP objective 'MQTT_broker' to
announce the address and port of the MQTT broker."""

# Released under the BSD "Revised" License.
# Some code borrowed from Antje Neve
#                                                     
# Copyright (C) 2026 Brian E. Carpenter.                  
# All rights reserved.

# 20261002 First version
# 20261006 Added exception handling

import paho.mqtt.client as mqtt
from paho.mqtt.properties import Properties
from paho.mqtt.packettypes import PacketTypes
import sys
import time
import socket
import json
sys.path.insert(0, '..') # in case graspi.py is one level up
import graspi

TOPIC = "trial/GRASP/test"

ASA_name = "Publisher" # Arbitrary ASA name, unique in the GRASP instance.

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

# The ASA name is arbitrary - it just needs to be
# unique in the GRASP instance.

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
    time.sleep(30)

BROKER = str(new_broker.source.locator)
PORT = new_broker.source.port
if new_broker.source.protocol != socket.IPPROTO_TCP:
    graspi.tprint("Wrong protocol")
    sys.exit()
    
####################################
# Define MQTT callbacks
####################################

def on_connect(client, userdata, flags, reason_code, properties):
    graspi.tprint("Connect:", reason_code)

def on_publish(client, userdata, mid, reason_code, properties):
    graspi.tprint("Published, mid:", mid, "Result:", reason_code)

######################
# Prepare a payload
# (looks like network intent)
######################

pay_dict = {
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

######################
# Prepare MQTT environment
######################

client = mqtt.Client(
    callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
    client_id="GRASP-publisher",
    protocol=mqtt.MQTTv5,
)

client.on_connect = on_connect
client.on_publish = on_publish

######################
# Publish payload for ever
######################

client.connect(BROKER, PORT, keepalive=60)
client.loop_start()

while True:
    current_time = time.strftime("%H:%M:%S", time.localtime())
    pay_dict["timestamp"] = f"Local Time: {current_time}"
    payload = json.dumps(pay_dict)

    props = Properties(PacketTypes.PUBLISH)
    props.MessageExpiryInterval = 60
    props.UserProperty = [("GRASP", "test"), ("protocol", "mqtt5")]

    result = client.publish(
        TOPIC,
        payload=payload,
        qos=1,
        retain=False,
        properties=props,
    )

    graspi.tprint("Sending:", payload)
    try:
        result.wait_for_publish()
    except Exception as e:
        graspi.tprint("Publishing error", str(e))

    time.sleep(60)
