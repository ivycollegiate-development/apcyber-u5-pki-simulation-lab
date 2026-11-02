#!/usr/bin/env python3
"""
PKI Simulation Lab Implementation
Creates Root CA, Intermediate CA, issues certificates, verifies chains,
implements CRL/OCSP, and demonstrates mTLS.
"""
import os
import sys
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, BestAvailableEncryption
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import ipaddress

# ============================================================
# Configuration
# ============================================================

CA_DIR = "ca"
ROOT_DIR = os.path.join(CA_DIR, "root_ca")
INTERMEDIATE_DIR = os.path.join(CA_DIR, "intermediate_ca")
CERTS_DIR = os.path.join(CA_DIR, "certs")
CRL_DIR = os.path.join(CA_DIR, "crl")

for d in [ROOT_DIR, INTERMEDIATE_DIR, CERTS_DIR, CRL_DIR]:
    os.makedirs(d, exist_ok=True)

# ============================================================
# Helper Functions
# ============================================================

def generate_rsa_key(key_size=4096):
    """Generate RSA private key."""
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)

def generate_ec_key(curve=ec.SECP384R1()):
    """Generate ECDSA private key."""
    return ec.generate_private_key(curve)

def save_key(key, path, password=None):
    """Save private key to file."""
    encryption = BestAvailableEncryption(password) if password else NoEncryption()
    with open(path, "wb") as f:
        f.write(key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        ))

def load_key(path, password=None):
    """Load private key from file."""
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=password)

def save_cert(cert, path):
    """Save certificate to file."""
    with open(path, "wb") as f:
        f.write(cert.public_bytes(Encoding.PEM))

def load_cert(path):
    """Load certificate from file."""
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())

def build_subject(cn, org="MedPort", org_unit="PKI Lab", country="US", state="California", locality="San Francisco"):
    """Build X.509 subject name."""
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, org_unit),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])

# ============================================================
# Phase 1: Root CA
# ============================================================

def create_root_ca(key_type="rsa", key_size=4096):
    print("[*] Creating Root CA...")
    
    # Generate key
    if key_type == "rsa":
        key = generate_rsa_key(key_size)
    else:
        key = generate_ec_key()
    
    save_key(key, os.path.join(ROOT_DIR, "root_ca.key"))
    
    # Build certificate
    subject = build_subject("MedPort Root CA")
    
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(subject)  # Self-signed
    builder = builder.public_key(key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(datetime.datetime.utcnow())
    builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))  # 10 years
    
    # Extensions
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=1),
        critical=True
    )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    )
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
        critical=False
    )
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
        critical=False
    )
    
    # Sign
    cert = builder.sign(key, hashes.SHA256())
    save_cert(cert, os.path.join(ROOT_DIR, "root_ca.crt"))
    
    print(f"[+] Root CA created: {ROOT_DIR}/root_ca.crt")
    print(f"    Subject: {cert.subject}")
    print(f"    Valid: {cert.not_valid_before} to {cert.not_valid_after}")
    print(f"    Key Usage: {cert.extensions.get_extension_for_class(x509.KeyUsage).value}")
    print(f"    Basic Constraints: {cert.extensions.get_extension_for_class(x509.BasicConstraints).value}")
    
    return key, cert

# ============================================================
# Phase 2: Intermediate CA
# ============================================================

def create_intermediate_ca(root_key, root_cert, key_type="rsa", key_size=4096):
    print("\n[*] Creating Intermediate CA...")
    
    # Generate key
    if key_type == "rsa":
        key = generate_rsa_key(key_size)
    else:
        key = generate_ec_key()
    
    save_key(key, os.path.join(INTERMEDIATE_DIR, "intermediate_ca.key"))
    
    # Create CSR
    subject = build_subject("MedPort Intermediate CA")
    csr_builder = x509.CertificateSigningRequestBuilder()
    csr_builder = csr_builder.subject_name(subject)
    csr_builder = csr_builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=0),
        critical=True
    )
    csr_builder = csr_builder.add_extension(
        x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    )
    csr = csr_builder.sign(key, hashes.SHA256())
    
    # Save CSR
    with open(os.path.join(INTERMEDIATE_DIR, "intermediate_ca.csr"), "wb") as f:
        f.write(csr.public_bytes(Encoding.PEM))
    
    # Sign with Root CA
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(root_cert.subject)
    builder = builder.public_key(key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(datetime.datetime.utcnow())
    builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1825))  # 5 years
    
    # Extensions
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=0),
        critical=True
    )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    )
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
        critical=False
    )
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
        critical=False
    )
    
    cert = builder.sign(root_key, hashes.SHA256())
    save_cert(cert, os.path.join(INTERMEDIATE_DIR, "intermediate_ca.crt"))
    
    print(f"[+] Intermediate CA created: {INTERMEDIATE_DIR}/intermediate_ca.crt")
    print(f"    Subject: {cert.subject}")
    print(f"    Issuer: {cert.issuer}")
    print(f"    Basic Constraints: {cert.extensions.get_extension_for_class(x509.BasicConstraints).value}")
    
    return key, cert

# ============================================================
# Phase 3: End-Entity Certificates
# ============================================================

def issue_certificate(ca_key, ca_cert, cn, san_list, key_usage, eku_list, filename, key_type="rsa", key_size=2048, days=365):
    print(f"\n[*] Issuing certificate: {cn}")
    
    # Generate key
    if key_type == "rsa":
        key = generate_rsa_key(key_size)
    else:
        key = generate_ec_key()
    
    save_key(key, os.path.join(CERTS_DIR, f"{filename}.key"))
    
    # Build SAN extension
    san_entries = []
    for san in san_list:
        if san.startswith("DNS:"):
            san_entries.append(x509.DNSName(san[4:]))
        elif san.startswith("IP:"):
            san_entries.append(x509.IPAddress(ipaddress.ip_address(san[3:])))
        elif san.startswith("email:"):
            san_entries.append(x509.RFC822Name(san[6:]))
        else:
            san_entries.append(x509.DNSName(san))
    
    subject = build_subject(cn)
    
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.public_key(key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(datetime.datetime.utcnow())
    builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=days))
    
    # Extensions
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True
    )
    builder = builder.add_extension(
        key_usage,
        critical=True
    )
    builder = builder.add_extension(
        x509.ExtendedKeyUsage(eku_list),
        critical=True
    )
    builder = builder.add_extension(
        x509.SubjectAlternativeName(san_entries),
        critical=False
    )
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
        critical=False
    )
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
        critical=False
    )
    
    cert = builder.sign(ca_key, hashes.SHA256())
    save_cert(cert, os.path.join(CERTS_DIR, f"{filename}.crt"))
    
    print(f"[+] Certificate issued: {CERTS_DIR}/{filename}.crt")
    print(f"    Subject: {cert.subject}")
    print(f"    SAN: {[str(s) for s in san_entries]}")
    print(f"    Key Usage: {cert.extensions.get_extension_for_class(x509.KeyUsage).value}")
    print(f"    EKU: {[str(e) for e in cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value]}")
    
    return key, cert

def issue_all_certificates(intermediate_key, intermediate_cert):
    print("\n" + "=" * 50)
    print("ISSUING END-ENTITY CERTIFICATES")
    print("=" * 50)
    
    # Server certificate (TLS)
    server_ku = x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=True,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False
    )
    issue_certificate(
        intermediate_key, intermediate_cert,
        "MedPort Server",
        ["DNS:localhost", "IP:127.0.0.1"],
        server_ku,
        [ExtendedKeyUsageOID.SERVER_AUTH],
        "server"
    )
    
    # Client 1 (Alice)
    client_ku = x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=True,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False
    )
    issue_certificate(
        intermediate_key, intermediate_cert,
        "Alice MedPort",
        ["email:alice@medport.local"],
        client_ku,
        [ExtendedKeyUsageOID.CLIENT_AUTH],
        "client_alice"
    )
    
    # Client 2 (Bob)
    issue_certificate(
        intermediate_key, intermediate_cert,
        "Bob MedPort",
        ["email:bob@medport.local"],
        client_ku,
        [ExtendedKeyUsageOID.CLIENT_AUTH],
        "client_bob"
    )
    
    # Revoked client (for revocation testing)
    revoked_key, revoked_cert = issue_certificate(
        intermediate_key, intermediate_cert,
        "Revoked User",
        ["email:revoked@medport.local"],
        client_ku,
        [ExtendedKeyUsageOID.CLIENT_AUTH],
        "client_revoked"
    )
    
    return revoked_cert.serial_number

# ============================================================
# Phase 4: Certificate Chain Verification
# ============================================================

def verify_chain(leaf_cert, intermediate_cert, root_cert):
    print(f"\n[*] Verifying chain for: {leaf_cert.subject}")
    
    # Build chain
    chain = [leaf_cert, intermediate_cert, root_cert]
    
    # Verify each link
    for i in range(len(chain) - 1):
        child = chain[i]
        parent = chain[i + 1]
        
        # Check issuer == parent subject
        if child.issuer != parent.subject:
            print(f"  ✗ ISSUER MISMATCH: {child.issuer} != {parent.subject}")
            return False
        
        # Verify signature
        try:
            child.verify_directly_issued_by(parent)
            print(f"  ✓ Signature valid: {child.subject} <- {parent.subject}")
        except Exception as e:
            print(f"  ✗ Signature INVALID: {e}")
            return False
        
        # Check validity period
        now = datetime.datetime.utcnow()
        if now < child.not_valid_before or now > child.not_valid_after:
            print(f"  ✗ EXPIRED/NOT YET VALID: {child.not_valid_before} to {child.not_valid_after}")
            return False
        print(f"  ✓ Validity period OK")
        
        # Check Basic Constraints
        try:
            bc = child.extensions.get_extension_for_class(x509.BasicConstraints).value
            if bc.ca and i == 0:  # Leaf should not be CA
                print(f"  ✗ Leaf certificate marked as CA!")
                return False
            print(f"  ✓ Basic Constraints: CA={bc.ca}, pathlen={bc.path_length}")
        except x509.ExtensionNotFound:
            print(f"  ✗ Basic Constraints missing")
            return False
    
    print(f"  ✓ Chain verification PASSED")
    return True

# ============================================================
# Phase 5: Revocation (CRL + OCSP)
# ============================================================

def create_crl(ca_key, ca_cert, revoked_serials, reason=x509.ReasonFlags.key_compromise):
    print("\n[*] Creating CRL...")
    
    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.last_update(datetime.datetime.utcnow())
    builder = builder.next_update(datetime.datetime.utcnow() + datetime.timedelta(days=30))
    
    for serial in revoked_serials:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(datetime.datetime.utcnow())
            .add_extension(x509.CRLReason(reason), critical=False)
            .build()
        )
    
    # Add Authority Key Identifier
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
        critical=False
    )
    
    crl = builder.sign(ca_key, hashes.SHA256())
    
    crl_path = os.path.join(CRL_DIR, "intermediate.crl")
    with open(crl_path, "wb") as f:
        f.write(crl.public_bytes(Encoding.PEM))
    
    print(f"[+] CRL created: {crl_path}")
    print(f"    Revoked serials: {[hex(s) for s in revoked_serials]}")
    
    return crl

def check_crl(crl, serial):
    """Check if serial is in CRL."""
    for revoked in crl:
        if revoked.serial_number == serial:
            return True, revoked.revocation_date
    return False, None

# Simple OCSP responder (simplified)
class SimpleOCSPResponder:
    def __init__(self, ca_key, ca_cert, crl):
        self.ca_key = ca_key
        self.ca_cert = ca_cert
        self.crl = crl
    
    def check_status(self, serial):
        """Return 'good', 'revoked', or 'unknown'."""
        revoked, rev_date = check_crl(self.crl, serial)
        if revoked:
            return "revoked", rev_date
        # In real OCSP, would check issued certs database
        # For lab, assume if not in CRL and issued by us -> good
        return "good", None

# ============================================================
# Main Lab Execution
# ============================================================

def run_full_lab():
    print("=" * 60)
    print("PKI SIMULATION LAB - FULL EXECUTION")
    print("=" * 60)
    
    # Phase 1: Root CA
    root_key, root_cert = create_root_ca()
    
    # Phase 2: Intermediate CA
    intermediate_key, intermediate_cert = create_intermediate_ca(root_key, root_cert)
    
    # Phase 3: End-entity certificates
    revoked_serial = issue_all_certificates(intermediate_key, intermediate_cert)
    
    # Phase 4: Chain verification
    print("\n" + "=" * 50)
    print("CHAIN VERIFICATION")
    print("=" * 50)
    
    for cert_name in ["server", "client_alice", "client_bob", "client_revoked"]:
        cert = load_cert(os.path.join(CERTS_DIR, f"{cert_name}.crt"))
        verify_chain(cert, intermediate_cert, root_cert)
    
    # Phase 5: Revocation
    print("\n" + "=" * 50)
    print("REVOCATION (CRL + OCSP)")
    print("=" * 50)
    
    crl = create_crl(intermediate_key, intermediate_cert, [revoked_serial])
    
    # Check CRL
    for cert_name in ["server", "client_alice", "client_bob", "client_revoked"]:
        cert = load_cert(os.path.join(CERTS_DIR, f"{cert_name}.crt"))
        revoked, date = check_crl(crl, cert.serial_number)
        status = "REVOKED" if revoked else "GOOD"
        print(f"  {cert_name}: {status}")
    
    # OCSP
    ocsp = SimpleOCSPResponder(intermediate_key, intermediate_cert, crl)
    for cert_name in ["server", "client_alice", "client_bob", "client_revoked"]:
        cert = load_cert(os.path.join(CERTS_DIR, f"{cert_name}.crt"))
        status, date = ocsp.check_status(cert.serial_number)
        print(f"  OCSP {cert_name}: {status}")
    
    print("\n" + "=" * 60)
    print("PKI LAB COMPLETE!")
    print("=" * 60)
    print(f"Root CA: {ROOT_DIR}/root_ca.crt")
    print(f"Intermediate CA: {INTERMEDIATE_DIR}/intermediate_ca.crt")
    print(f"Certificates: {CERTS_DIR}/*.crt")
    print(f"CRL: {CRL_DIR}/intermediate.crl")

if __name__ == "__main__":
    run_full_lab()