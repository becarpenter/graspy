"""This is a proof of concept for ODevID support for CASA,
Corporate Authorized Signing Authority, described in
draft-carpenter-anima-otp-casa. 
"""

# Released under the BSD "Revised" License.
#                                                     
# Copyright (C) 2026 Brian E. Carpenter.                  
# All rights reserved.

# Adapted from code proffered by Google AI

# 20260903 First version

from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import warnings

def create_odevid(token, key_file, cert_file):
    """The token (a meaningless string) is converted into an ODevID, which is
in IEEE 802.1AR IDevID format, represented as a PEM file. The PEM file and the
corresponding private key are saved to disk."""
    
    # 1. Generate the Device Private Key (ECC is standard for modern 802.1AR)
    private_key = ec.generate_private_key(ec.SECP384R1())

    # 2. Define Device Identity Information
    # IEEE 802.1AR strongly recommends including the manufacturer and serial number.
    manufacturer = "Self"
    model = "Device"
    serial_number = token
    
    # The Common Name (CN) typically combines these elements
    common_name = f"{manufacturer} {model} {serial_number}"

    # 3. Set Up Certificate Validity
    # IEEE 802.1AR IDevIDs represent permanent hardware identity.
    # They often use a "notAfter" date far in the future or a generalized time format.
    not_valid_before_utc = datetime.now(timezone.utc)
    not_valid_after_utc = not_valid_before_utc + timedelta(days=365 * 30) # 30 years

    # 4. Build the Subject Name
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, manufacturer),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.SERIAL_NUMBER, serial_number),
    ])

    # For an IDevID (Self-Signed or Issuer-Signed), the issuer matches the CA.
    # For an ODevID we create a self-signed object.
    issuer = subject 

    # 5. Build the Certificate
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before_utc)
        .not_valid_after(not_valid_after_utc)
    )

    # 6. Add IEEE 802.1AR Required & Recommended Extensions
    # Base Constraints: Must be a non-CA end-entity certificate
    cert_builder = cert_builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True
    )

    # Key Usage: Digital Signature and Key Encipherment/Agreement
    cert_builder = cert_builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=True,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    )

    # Extended Key Usage: Client Authentication (standard for network access/802.1X)
    cert_builder = cert_builder.add_extension(
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
        critical=False
    )

    # 7. Sign the certificate with the private key
    cert = cert_builder.sign(private_key, hashes.SHA384())

    # 8. Serialize and Save Key and Certificate
    pem_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    pem_cert = cert.public_bytes(serialization.Encoding.PEM)

    with open(key_file, "wb") as f:
        f.write(pem_key)

    with open(cert_file, "wb") as f:
        f.write(pem_cert)

    return

def parse_idevid(file):
    """Parse given IDevID PEM file (or bytes)"""
    if type(file).__name__ == "bytes":
        cert_pem_bytes = file
    else:
        cert_pem_bytes = open(file, "rb").read()
        
    # Load the X.509 certificate
    cert = x509.load_pem_x509_certificate(cert_pem_bytes, default_backend())
    
    # Extract the main properties
##    print(f"Subject: {cert.subject}")
##    print(f"Issuer: {cert.issuer}")
##    print(f"Serial Number: {cert.serial_number}")
##    print(f"Not Valid Before: {cert.not_valid_before}")
##    print(f"Not Valid After: {cert.not_valid_after}")

    with warnings.catch_warnings():
        warnings.simplefilter('ignore')    # deprecated feature...
        nvb = cert.not_valid_before
        nva = cert.not_valid_after
    now = datetime.now()
    if now < nvb or now > nva:
        return(False)

##    # Extract hardware data (e.g., TCG and IEEE 802.1AR DevID extensions)
##    for extension in cert.extensions:
##        print(f"\nExtension OID: {extension.oid.dotted_string}")
##        print(f"Critical: {extension.critical}")
##        print(f"Value: {extension.value.value.hex()}")

    serial = (str(cert.subject).split("2.5.4.5=")[1][:-2]) # a bit of a hack...
    issuer = (str(cert.subject).split("(O=")[1].split(",")[0]) # ditto...
    return({"serial-number":serial, "idevid-issuer":issuer})
