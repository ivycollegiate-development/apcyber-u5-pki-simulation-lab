#!/usr/bin/env python3
"""
Test script for GitHub Actions validation of PKI Simulation Lab.
Validates pki_lab.py execution, certificate properties, and findings_template.csv.
"""
import csv
import sys
import os
import subprocess
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtendedKeyUsageOID

EXPECTED_FINDINGS = {
    "PKI-001": {"component": "Root CA", "test": "Self-signed verification", "expected": "Valid", "pass_fail": "PASS"},
    "PKI-002": {"component": "Root CA", "test": "Key Usage", "expected": "keyCertSign+cRLSign", "pass_fail": "PASS"},
    "PKI-003": {"component": "Root CA", "test": "Basic Constraints", "expected": "CA:TRUE pathlen:1", "pass_fail": "PASS"},
    "PKI-004": {"component": "Intermediate CA", "test": "Signed by Root", "expected": "Valid signature", "pass_fail": "PASS"},
    "PKI-005": {"component": "Intermediate CA", "test": "Basic Constraints", "expected": "CA:TRUE pathlen:0", "pass_fail": "PASS"},
    "PKI-006": {"component": "Server Cert", "test": "Key Usage", "expected": "digitalSignature+keyEncipherment", "pass_fail": "PASS"},
    "PKI-007": {"component": "Server Cert", "test": "EKU", "expected": "serverAuth", "pass_fail": "PASS"},
    "PKI-008": {"component": "Server Cert", "test": "SAN", "expected": "DNS:localhost IP:127.0.0.1", "pass_fail": "PASS"},
    "PKI-009": {"component": "Client Cert", "test": "Key Usage", "expected": "digitalSignature+keyAgreement", "pass_fail": "PASS"},
    "PKI-010": {"component": "Client Cert", "test": "EKU", "expected": "clientAuth", "pass_fail": "PASS"},
    "PKI-011": {"component": "Chain Verification", "test": "Leaf→Intermediate→Root", "expected": "Valid chain", "pass_fail": "PASS"},
    "PKI-012": {"component": "Chain Verification", "test": "Expired cert rejected", "expected": "Rejected", "pass_fail": "PASS"},
    "PKI-013": {"component": "Chain Verification", "test": "Wrong EKU rejected", "expected": "Rejected", "pass_fail": "PASS"},
    "PKI-014": {"component": "Revocation", "test": "CRL includes revoked cert", "expected": "Listed", "pass_fail": "PASS"},
    "PKI-015": {"component": "Revocation", "test": "OCSP returns revoked", "expected": "revoked", "pass_fail": "PASS"},
    "PKI-016": {"component": "mTLS", "test": "Valid client connects", "expected": "Success", "pass_fail": "PASS"},
    "PKI-017": {"component": "mTLS", "test": "Revoked client rejected", "expected": "Rejected", "pass_fail": "PASS"},
    "PKI-018": {"component": "mTLS", "test": "No client cert rejected", "expected": "Rejected", "pass_fail": "PASS"},
}

REQUIRED_FINDING_IDS = set(EXPECTED_FINDINGS.keys())
REQUIRED_COLUMNS = ["finding_id", "component", "test", "expected", "actual", "pass_fail", "notes"]

def validate_findings(csv_path):
    errors = []
    warnings = []
    
    if not os.path.exists(csv_path):
        errors.append(f"File not found: {csv_path}")
        return errors, warnings
    
    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    
    if reader.fieldnames != REQUIRED_COLUMNS:
        errors.append(f"Invalid columns. Expected: {REQUIRED_COLUMNS}, Got: {reader.fieldnames}")
        return errors, warnings
    
    found_ids = set()
    for i, row in enumerate(rows):
        finding_id = row.get("finding_id", "").strip()
        if not finding_id:
            errors.append(f"Row {i+2}: Missing finding_id")
            continue
        
        if finding_id in found_ids:
            errors.append(f"Row {i+2}: Duplicate finding_id: {finding_id}")
        found_ids.add(finding_id)
        
        if finding_id not in EXPECTED_FINDINGS:
            warnings.append(f"Row {i+2}: Unexpected finding_id: {finding_id}")
        else:
            expected = EXPECTED_FINDINGS[finding_id]
            for field, expected_value in expected.items():
                actual = row.get(field, "").strip()
                if actual != expected_value:
                    errors.append(f"Row {i+2} ({finding_id}): {field} mismatch. Expected '{expected_value}', got '{actual}'")
        
        if row.get("pass_fail", "").strip() != "PASS":
            warnings.append(f"Row {i+2} ({finding_id}): pass_fail is not PASS")
    
    for exp_id in REQUIRED_FINDING_IDS:
        if exp_id not in found_ids:
            errors.append(f"Missing expected finding: {exp_id}")
    
    return errors, warnings

def check_certificate_properties():
    """Verify generated certificates have correct properties."""
    errors = []
    warnings = []
    
    cert_files = {
        "root_ca": "../ca/root_ca/root_ca.crt",
        "intermediate_ca": "../ca/intermediate_ca/intermediate_ca.crt",
        "server": "../ca/certs/server.crt",
        "client_alice": "../ca/certs/client_alice.crt",
        "client_bob": "../ca/certs/client_bob.crt",
        "client_revoked": "../ca/certs/client_revoked.crt",
    }
    
    for name, path in cert_files.items():
        full_path = os.path.join(os.path.dirname(__file__), path)
        if not os.path.exists(full_path):
            errors.append(f"Certificate not found: {name} at {path}")
            continue
        
        try:
            with open(full_path, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())
            
            print(f"[*] Checking {name}: {cert.subject.rfc4514_string()}")
            
            # Basic validity
            import datetime
            now = datetime.datetime.utcnow()
            if now < cert.not_valid_before or now > cert.not_valid_after:
                warnings.append(f"{name}: Certificate not currently valid")
            
            # Check Basic Constraints
            try:
                bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
                print(f"    Basic Constraints: CA={bc.ca}, pathlen={bc.path_length}")
            except x509.ExtensionNotFound:
                warnings.append(f"{name}: Basic Constraints extension missing")
            
            # Check Key Usage
            try:
                ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
                print(f"    Key Usage: {ku}")
            except x509.ExtensionNotFound:
                warnings.append(f"{name}: Key Usage extension missing")
            
            # Check EKU
            try:
                eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
                print(f"    EKU: {[str(e) for e in eku]}")
            except x509.ExtensionNotFound:
                if name not in ["root_ca", "intermediate_ca"]:
                    warnings.append(f"{name}: EKU extension missing")
            
            # Check SAN
            try:
                san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                print(f"    SAN: {[str(s) for s in san]}")
            except x509.ExtensionNotFound:
                if name not in ["root_ca", "intermediate_ca"]:
                    warnings.append(f"{name}: SAN extension missing")
                    
        except Exception as e:
            errors.append(f"Failed to parse {name}: {e}")
    
    return errors, warnings

def test_pki_lab():
    """Run pki_lab.py and verify it executes."""
    errors = []
    warnings = []
    try:
        result = subprocess.run(
            [sys.executable, "pki_lab.py"],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=os.path.dirname(os.path.abspath(__file__))
        )
        if result.returncode != 0:
            errors.append(f"pki_lab.py exited with code {result.returncode}: {result.stderr}")
        else:
            print("[*] pki_lab.py ran successfully")
            if "PKI LAB COMPLETE!" not in result.stdout:
                warnings.append("pki_lab.py output missing completion message")
    except subprocess.TimeoutExpired:
        errors.append("pki_lab.py timed out")
    except Exception as e:
        errors.append(f"Failed to run pki_lab.py: {e}")
    
    return errors, warnings

if __name__ == "__main__":
    all_errors = []
    all_warnings = []
    
    print("[*] Validating findings_template.csv...")
    f_errors, f_warnings = validate_findings("findings_template.csv")
    all_errors.extend(f_errors)
    all_warnings.extend(f_warnings)
    
    print("[*] Running pki_lab.py to generate certificates...")
    p_errors, p_warnings = test_pki_lab()
    all_errors.extend(p_errors)
    all_warnings.extend(p_warnings)
    
    print("[*] Checking certificate properties...")
    c_errors, c_warnings = check_certificate_properties()
    all_errors.extend(c_errors)
    all_warnings.extend(c_warnings)
    
    if all_warnings:
        print("\n[WARNINGS]")
        for w in all_warnings:
            print(f"  ! {w}")
    
    if all_errors:
        print("\n[ERRORS]")
        for e in all_errors:
            print(f"  ✗ {e}")
        print(f"\nValidation FAILED: {len(all_errors)} errors")
        sys.exit(1)
    else:
        print("\n[SUCCESS] All validations passed!")
        sys.exit(0)