# graspy
Python 3 demo code for GRASP protocol

This repository is for a Python 3 demonstration implementation of GRASP, the Generic Autonomic Signaling Protocol developed in the IETF ANIMA working group. It also contains some demonstration applications.

This code IS NOT INTENDED FOR PRODUCTION USE. See the license and disclaimer in the grasp.py source file.

Status on 2017-07-01:

These versions use the latest GRASP API with integer error codes.
INCOMPATIBLE WITH PYTHON GRASP RELEASES BEFORE 2017!

Also the assigned GRASP port number, 7017, is now used.
INCOMPATIBLE WITH ALL PREVIOUS PYTHON GRASP RELEASES!

They are coded in Python 3 and will fail with Python 2.

The documentation for grasp.py and acp.py
is in the file graspy.pdf

There's a short overview presentation in
the file AN-overview.pdf

The code was tested only on Windows 7 Linux and MacOS so far. In theory,
the code will work on any host with Winsock2 or Posix compliant TCP/IPv6.
When testing ASAs, run each one in a separate instance of Python 3.
You need to be Administrator (Windows) or su (Linux).

When it asks
  Test mode (many extra diagnostics)? Y/N:
type n unless you want very detailed diagnostics.

When it asks
  Listen to own multicasts? Y/N:
type y if running on a single machine. Although all instances will share
the same IPv6 address, everything should work exactly as if each
instance was on a separate machine.

If you have the luxury of testing with several machines on a network, type n.
This has been tested between Windows and Linux on a simple network including
a physical layer loop, and on non-looped topologies with various mixtures of
Linux, Windows 7 and MacOS.
