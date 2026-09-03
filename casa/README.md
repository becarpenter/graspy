# casa
## Python proof of concept for CASA

This folder contains a Python 3 proof of concept implementation of CASA (Corporate Authorized Signing Authority), including a one-time pad for authorizing device identity - see 
[draft-carpenter-anima-otp-casa](https://datatracker.ietf.org/doc/draft-carpenter-anima-otp-casa/).
Readers also need to be familiar with
[BRSKI](https://www.rfc-editor.org/info/rfc8995).

Tested on Python 3.14 on Windows 11, Python 3.12 on Linux kernel 7.0.0-28, and Python 3.11 on Windows 10.

This code IS NOT INTENDED FOR PRODUCTION USE. See the license and disclaimers in the grasp.py source file.

It's amateur code from a security point of view. DO NOT trust it in the slightest.

## Components

`casa.py` - the CASA itself and its built-in BRSKI registrar. This is intended to run indefinitely on a single trusted host inside a (corporate) domain.

`casa-installer.py` - the installer that can install a one-time token (an ODevID, in IDevID format) on a pledge system.

`casa-proxy.py` - a BRSKI proxy. This is intended to run indefinitely on routers within the domain.

`casa-pledge.py` - a program that should only need to run exactly once on a pledge (computer) that is thereby onboarded by the BRSKI process.

All devices need a Python 3 environment. On Linux, `casa.py` needs root (`sudo su`) privilege (it listens on a system port). 

## Dependencies

`casa_setup.py` - various utilities and declarations used by the other components (except `casa-proxy.py`).

`casa_odevid.py` - utility functions to create and parse an ODevID.

`graspi.py`, `grasp.py` and `acp.py`, Python code for [GRASP](https://www.rfc-editor.org/info/rfc8990).

Various standard Python libraries.

## Usage

Run `casa.py` on a central machine. The first time, it will create a file space for itself, including a log file that will expand for ever. For this proof-of-concept, the log file would serve for audit purposes, and tokens, certificates etc., are stored in the same file space. They are not encrypted (but they should be, in real life). The CASA code is intended to be reasonably robust and if it exits, upon restart it will pick up the latest data from the file space. However, any interrupted transaction will be lost.

Depending on your setup, `casa.py` may need administrator/root privilege.

CASA has a very simple GUI. It will offer periodically to manufacture an APADL (Agent one-time-PAD List, pronounced "a Paddle"). You will need at least one APADL, which is basically an empty USB memory stick. Theoretically, you just plug it in and CASA will do the rest. Then remove the APADL and keep it safe.
(The APADL should be encrypted in real life.) It may be convenient to copy all 9 of the above Python files onto the stick.

Run `casa-proxy.py` on relevant routers, i.e. the routers in the
[Autonomic Control Plane (ACP)](https://www.rfc-editor.org/info/rfc8994).
It needs to run forever, but it stores no state and could be restarted any time.

To add a pledge to the BRSKI environment, there are several steps.

1. Plug your APADL memory stick into the pledge.

2. Run `casa-installer.py` - it will create a file space for the pledge, and then create and install its ODevID (both a certificate and a private key). 

3. Remove the APADL and keep it safe.

4. Run `casa-pledge.py` on the pledge. It will execute (an approximation to) the BRSKI process, which will allow the pledge to onboard itself almost as though it had a genuine manufacturer-installed IDevID.

That's as far as this code goes. It does _not_ support the ACP process at all.

Both `casa.py` and `casa-pledge.py` include optional test modes for debugging purposes. Use with care.

## File spaces

On Windows, the filespaces used are `C:ProgramData/Temp/casa` and `C:ProgramData/Temp/pledge`. On Unixish systems, they are `/tmp/casa` and `/tmp/pledge`. If you don't like those choices, you'll need to edit one line in `casa_setup.py`

## Coding note

I tried and I tried to use various Python crypto libraries for CMS signing and verifying, but on Windows no combination worked for me. So in the end I used OpenSSL command line functions (`see sign_json()` and `verify_json()` in `casa_setup.py`). It's horribly inefficient, so if anyone can do better, and provably portably between Windows and Linux, please shout out.

## Acknowledgements

Thanks to Google AI for various code fragments (not including the ones that turned out to be hallucinations).

Thanks to [abrox](https://github.com/abrox/simplest) for the code of an elementary EST server, which was originally licensed under the MIT License.
