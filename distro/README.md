# pub/sub
## Python proof of concept for simplified pub/sub in ANIMA GRASP context

This folder contains a Python 3 proof of concept implementation of 
draft-carpenter-anima-distro

Tested on Python 3.14 on Windows 11, Python 3.12 on Linux kernel 7.0.0-28, and Python 3.11 on Windows 10.

This code IS NOT INTENDED FOR PRODUCTION USE. See the license and disclaimers in the `grasp.py` source file.

It's amateur code from a security point of view. DO NOT trust it in the slightest.

## Components

`grasp.py` - This is a specially patched version of GRASP that supports the simplified pub/sub model. In theory, it should be backwards compatible but I kept it separate as a precaution.

`publish.py` - a very simple publisher ASA that floods out a subscribable object (containing some artificial JSON intent)

`subscribe.py` - a subscriber ASA that suscribes and receives the JSON intent. It includes the
`subscribe_topic()` and `unsubscribe_topic()` functions. With a bit more work they could
be embedded in `grasp.py`.

## Conclusion

The integration of this simplified pub/sub in the ANIMA/GRASP ecosystem seems quite straightforward. I think the proposal in draft-ietf-anima-grasp-distribution would be a lot more work.
 