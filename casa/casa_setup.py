"""These are common definitions for the CASA suite."
"""

# Released under the BSD "Revised" License.
#                                                     
# Copyright (C) 2026 Brian E. Carpenter.                  
# All rights reserved.

# 20260901 First version

import os
import subprocess
import time
from datetime import datetime, timezone
import json
from base64 import b64encode as b64e
from base64 import b64decode as b64d
##from cryptography.hazmat.primitives import hashes
##from cryptography.hazmat.primitives.asymmetric import padding
##from cryptography.hazmat.primitives.serialization import load_pem_private_key
##from cryptography.hazmat.primitives.serialization import load_pem_public_key
##from cryptography.hazmat.primitives.asymmetric import ec
##from cryptography import x509

def crash(msg):
    """Display message for 10s and exit"""
    print(msg)
    time.sleep(10)
    exit(0)

def shcmd(cmd):
    """Execute shell command and return results"""
    #print("Debug: ",cmd)
    do_cmd = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    _out, _err = do_cmd.communicate()
    return(_err.decode('utf-8').strip(), _out.decode('utf-8').strip())

def wf(fn, array):
    """Write bytes array to file"""
    f = open(fn, "wb")
    for t in array:
        f.write(t)
    f.close()

def rf(fn, chunk_size):
    """Read binary file, return bytes array"""
    f = open(fn, "rb")
    array = []
    while chunk := f.read(chunk_size):
        array.append(chunk)
    f.close()
    return(array)

def timestamp():
    """Returns timestamp in correct string format"""
    return(datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))

def stripcert(cert):
    """Strips start/end markers from PEM string"""
    c = cert.replace("-----BEGIN CERTIFICATE-----","")
    return(c.replace("-----END CERTIFICATE-----","").replace("\n",""))

def sign_json(payload, cert_file, key_file, fpath):
    """Create and return CMS object"""
    content_file = fpath + "/content.txt"
    temp_file = fpath + "/temp.cms"
    payload = b64e(json.dumps(payload).encode("utf-8"))
    with open(content_file, "wb") as f:
        f.write(payload)
    make = "openssl cms -sign -in "+content_file+" -signer "+cert_file+\
            " -inkey "+key_file+" -nodetach -outform PEM -out "+temp_file
    err, result = shcmd(make)
    if err == "":
        with open(temp_file, "rb") as f:
            sig = f.read() 
    else:
        sig = None
    os.remove(content_file)
    os.remove(temp_file)
    return(sig)

def verify_json(cms, fpath):
    """Verify self-signed CMS object and return content as JSON"""
    temp_file = fpath+"/temp.cms"
    with open(temp_file, "wb") as f:
        f.write(cms.encode("utf-8"))
    check = "openssl cms -verify -in "+temp_file+" -inform PEM -noverify"
    err, result = shcmd(check)
    os.remove(temp_file)
    if 'successful' in err:
        return(json.loads(b64d(result).decode("utf-8")))
    else:
        return(None)

# OS-dependent file path

env_path = "C:/ProgramData/Temp" if os.name=="nt" else "/tmp"

# shorthand for RFC8995 artefacts

ivrv = "ietf-voucher-request:voucher"
ivv = "ietf-voucher:voucher"

# configurations

est_port = 443   # per RFC8995
radius = 6       # max hops for GRASP flooding
token_count = 100 # How many tokens we assign to an APDL
token_l = 8 # token length in bytes
nonce_l = 8 # nonce length in bytes

# token flags

# flag bit 0 -> token already claimed
# flag bit 1 -> token identfies an APDL
FREE = b'\x00'
CLAIMED = b'\x01'    # flag bit 0 on
CLAIMED_AS_APDL = b'\x03'  # both flags on


