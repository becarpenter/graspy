# mqtt
## Python proof of concept for using MQTT in AMIMA GRASP context

This folder contains a Python 3 proof of concept implementation of deploying
MQTT as a pub/sub mechanism in an [autonomic network](https://www.rfc-editor.org/info/rfc8993).
See
[draft-carpenter-anima-mqtt](https://datatracker.ietf.org/doc/draft-carpenter-anima-mqtt/)
for background.
Readers also need to be familiar with 
[GRASP](https://www.rfc-editor.org/info/rfc8990) and its [API](https://www.rfc-editor.org/info/rfc8991).

Tested on Python 3.14 on Windows 11, Python 3.12 on Linux kernel 7.0.0-28, and Python 3.11 on Windows 10.

This code IS NOT INTENDED FOR PRODUCTION USE. See the license and disclaimers in the `grasp.py` source file.

It's amateur code from a security point of view. DO NOT trust it in the slightest.

## Components

`Broker.py` - this announces an MQTT broker via GRASP M_FLOOD, using the GRASP objective `MQTT_broker`. The current version only works on Windows and requires the stand-alone `mosquitto` broker to be installed.

`Publisher.py` - a simple MQTT publisher that discovers the broker via GRASP and publishes a sample message formulated as a timestamped JSON management intent object

`Subscriber.py` - a simple MQTT subscriber that discovers the broker via GRASP and recieves the JSON intent. 

All devices need a Python 3 environment. The Publisher and Subscriber need the `paho-mqtt` module (version 3).

_Warning_: On Linux, `apt install python3-paho-mqtt`
installed an obsolete version (1.6.1); it was necessary to apply
`pip3 install --upgrade --break-system-packages paho-mqtt`
to fetch a current version (2.1.1).

## Usage

[Download](https://mosquitto.org/download/) and install `mosquitto.exe` as a service on a Windows machine, and ensure that `C:\Program Files\mosquitto\mosquitto.conf` includes:
~~~
listener 1883
allow_anonymous true
~~~
which will use the IANA-assigned TCP port for MQTT and avoid MQTT security. (The assumption is that in a real deployment, the ANIMA autonomic control plane will provide security.)

`Mosquitto` is also freely available for other operating systems, but this is left as an exercise for the reader.

Apart from that, the programs are pure Python apps but they need a [Python GRASP environment](https://github.com/becarpenter/graspy).