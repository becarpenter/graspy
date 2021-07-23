# graspy
Python 3 demo code for GRASP protocol

This repository is for a Python 3 demonstration implementation of GRASP, the Generic Autonomic Signaling Protocol developed in the IETF ANIMA working group, and its API. It also contains some demonstration applications.

This code IS NOT INTENDED FOR PRODUCTION USE. See the license and disclaimers in the graspi.py source file.

Overview: see GRASP-intro.pdf

Doc: see graspy.pdf

Status on 2021-07-22

Fixed the CBOR Tag 24 handling. It was (incompatibly) wrong before.

Status on 2021-05-22

Celebrating the publication of RFCs 8990-8995. Code here implements RFC8990, RFC8991 and RFC8992

Status on 2021-02-05

Added experimental ASA_loader.py, a proof-of-concept ASA ecosystem. Updated Briggs & Gray accordingly.
(Briggs_old and Gray_old still use the old API.)

Status on 2021-01-15

Added missing API features and added graspi.py as a wrapper that conforms to the approved official API. Some of the demos (graspitests, Briggs, Gray) have been updated to use the official API. Others will be updated as time permits.

Status on 2020-09-21

Added support for the insecure Link-Local mode (DULL)

Status on 2019-11-14:

Added gsend() and grecv(), a messaging channel over a GRASP session (not part of the IETF standard)

Status on 2019-10-30:

Added QUADS security and QUADSKI key infrastructure (not part of the IETF standard)

Status on 2019-01-26:

The grasp.py and acp.py modules module have been updated to
move the logic for finding interfaces and addresses into
acp.py. Thus the main module will work with any kind of ACP,
including a Layer 2 ACP.
INCOMPATIBLE WITH PYTHON GRASP RELEASES BEFORE 2019! Refresh
grasp.py and acp.py at the same time.

These versions use the latest GRASP API with integer error codes.
INCOMPATIBLE WITH PYTHON GRASP RELEASES BEFORE 2017!

Also the assigned GRASP port number, 7017, and the official
link-local multicast address ff02::13 are now used.
INCOMPATIBLE WITH PRE-2017 PYTHON GRASP RELEASES!

They are coded in Python 3 and will fail with Python 2.

The documentation for grasp.py and acp.py
is in the file graspy.pdf

There's a short overview presentation in
the file GRASP-intro.pdf

The code was tested only on Windows 7 and 10, Linux and MacOS so far. In theory,
the code will work on any host with Winsock2 or Posix compliant TCP/IPv6.
When testing ASAs, run each one in a separate instance of Python 3.
You might need to be Administrator (Windows) or su (Linux).

When it asks

  Test mode (many extra diagnostics)? Y/N:
  
type n unless you want very detailed diagnostics.

When it asks

  Diagnostics for inbound message parse errors? Y/N:
  
type y unless you really don't care about parse errors

When it asks

  Listen to own multicasts? Y/N:
  
type y if running on a single machine. Although all instances will share
the same IPv6 address, everything should work exactly as if each
instance was on a separate machine.

If you have the luxury of testing with several machines on a network, type n.
This has been tested between Windows and Linux on a simple network including
a physical layer loop, and on non-looped topologies with various mixtures of
Linux, Windows 7 and MacOS.

When it asks

  Insecure link-local mode (DULL)? Y/N:

type n unless you know what you are doing (see graspy.pdf for more).

When it asks

   Please enter the keying password for the domain.

type in a locally chosen domain password, or a null password to run
insecurely (see graspy.pdf for more).

