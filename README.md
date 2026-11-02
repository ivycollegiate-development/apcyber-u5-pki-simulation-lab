# AP Cyber Unit 5 Lab: PKI Simulation — Certificate Authority, Certificate Lifecycle, mTLS

**Course**: AP Computer Science Principles — Cybersecurity
**Unit**: 5 — Application & Data Security
**Topic**: 5.3 Cryptographic Primitives (Asymmetric/PKI), 5.4 PKI & Certificate Management

---

## Lab Overview

In this lab, you will build a **miniature Public Key Infrastructure (PKI)** from scratch. You will create a **Root CA**, an **Intermediate CA**, issue **end-entity certificates** (server + client), verify **certificate chains**, implement **OCSP/CRL checking**, and configure **mutual TLS (mTLS)** between a client and server.

---

## Learning Objectives

By the end of this lab, you will be able to:
- ☐ Generate RSA/ECDSA key pairs and Certificate Signing Requests (CSRs)
- ☐ Create a **Root CA** (self-signed) and **Intermediate CA** (signed by Root)
- ☐ Issue **server certificates** (TLS) and **client certificates** (mTLS)
- ☐ Verify **certificate chains** and validate extensions (Key Usage, EKU, SAN)
- ☐ Implement **certificate revocation** (CRL + OCSP)
- ☐ Configure and test **mutual TLS** authentication

---

## Prerequisites

- ☐ GitHub account with access to `ivycollegiate-development` organization
- ☐ Codespaces enabled (OpenSSL 3.x, Python 3.11 + `cryptography`)
- ☐ Pre-lab worksheet completed (Lesson: Pre-Lab PKI Simulation)

---

## Repository Structure

```
apcyber-u5-pki-simulation-lab/
├── pki_lab.py                 # Main PKI implementation
├── ca/
│   ├── root_ca/               # Root CA files
│   ├── intermediate_ca/       # Intermediate CA files
│   └── certs/                 # Issued certificates
├── mtls/
│   ├── server.py              # mTLS server
│   └── client.py              # mTLS client
├── findings_template.csv      # Submit findings here
├── tests/
│   └── test_pki.py            # GitHub Actions validation
├── .github/workflows/
│   └── grade.yml              # Auto-grading workflow
└── README.md                  # This file
```

---

## Lab Procedure

### Phase 1: Root CA Creation (10 min)

**File**: `pki_lab.py` → `create_root_ca()`

- Generate **RSA 4096** or **ECDSA P-384** key pair
- Create **self-signed Root CA certificate**:
  - `Basic Constraints: CA:TRUE, pathlen:1`
  - `Key Usage: keyCertSign, cRLSign`
  - `Subject Key Identifier`
  - `Authority Key Identifier`
  - Validity: **10 years**
- Save: `ca/root_ca/root_ca.key`, `ca/root_ca/root_ca.crt`

### Phase 2: Intermediate CA Creation (10 min)

**File**: `pki_lab.py` → `create_intermediate_ca()`

- Generate key pair for Intermediate CA
- Create **CSR** for Intermediate CA
- Sign with **Root CA**:
  - `Basic Constraints: CA:TRUE, pathlen:0`
  - `Key Usage: keyCertSign, cRLSign`
  - `Authority Key Identifier` → Root CA SKI
  - Validity: **5 years**
- Save: `ca/intermediate_ca/intermediate_ca.key`, `ca/intermediate_ca/intermediate_ca.crt`

### Phase 3: End-Entity Certificates (15 min)

**File**: `pki_lab.py` → `issue_certificate()`

Issue **4 certificates** signed by Intermediate CA:

| Cert | Purpose | Key Usage | Extended Key Usage | SAN |
|------|---------|-----------|-------------------|-----|
| **Server** | HTTPS/TLS | digitalSignature, keyEncipherment | serverAuth | DNS:localhost, IP:127.0.0.1 |
| **Client 1** | mTLS | digitalSignature, keyAgreement | clientAuth | email:alice@medport.local |
| **Client 2** | mTLS | digitalSignature, keyAgreement | clientAuth | email:bob@medport.local |
| **Revoked** | Test revocation | digitalSignature | clientAuth | email:revoked@medport.local |

### Phase 4: Certificate Chain Verification (10 min)

**File**: `pki_lab.py` → `verify_chain()`

- Build chain: **Leaf → Intermediate → Root**
- Verify:
  - Signature validation at each level
  - Validity period (notBefore/notAfter)
  - Basic Constraints (CA flags)
  - Key Usage matches purpose
  - EKU matches (serverAuth vs clientAuth)
  - SAN matches hostname/email

### Phase 5: Revocation (CRL + OCSP) (10 min)

**File**: `pki_lab.py` → `create_crl()`, `ocsp_responder()`

- **CRL**: Generate Certificate Revocation List from Intermediate CA
  - Include revoked certificate (serial number, revocation date, reason)
  - Sign with Intermediate CA key
  - Publish to `ca/crl/intermediate.crl`
- **OCSP**: Implement basic OCSP responder
  - Parse OCSP request (cert ID)
  - Check revocation status
  - Return signed OCSP response (good/revoked/unknown)

### Phase 6: Mutual TLS (mTLS) Demo (15 min)

**Files**: `mtls/server.py`, `mtls/client.py`

- **Server**: TLS with `verify_mode=CERT_REQUIRED`
  - Loads server cert + key
  - Loads CA chain (Root + Intermediate) as trust store
  - Requires client certificate
  - Prints client cert subject on connection
- **Client**: TLS with client cert + key
  - Loads client cert + key
  - Verifies server cert against CA chain
  - Connects to server, sends test message
- Test with:
  - Valid client cert → **success**
  - Revoked client cert → **rejected** (CRL/OCSP check)

### Phase 7: Documentation & Submission (5 min)

- ☐ Complete `findings_template.csv`
- ☐ Commit & push → GitHub Actions grades automatically

---

## Findings Template (findings_template.csv)

```csv
finding_id,component,test,expected,actual,pass_fail,notes
PKI-001,Root CA,Self-signed verification,Valid,Valid,PASS,Root CA verifies itself
PKI-002,Root CA,Key Usage,keyCertSign+cRLSign,keyCertSign+cRLSign,PASS,
PKI-003,Root CA,Basic Constraints,CA:TRUE pathlen:1,CA:TRUE pathlen:1,PASS,
PKI-004,Intermediate CA,Signed by Root,Valid signature,Valid signature,PASS,
PKI-005,Intermediate CA,Basic Constraints,CA:TRUE pathlen:0,CA:TRUE pathlen:0,PASS,
PKI-006,Server Cert,Key Usage,digitalSignature+keyEncipherment,digitalSignature+keyEncipherment,PASS,
PKI-007,Server Cert,EKU,serverAuth,serverAuth,PASS,
PKI-008,Server Cert,SAN,DNS:localhost IP:127.0.0.1,DNS:localhost IP:127.0.0.1,PASS,
PKI-009,Client Cert,Key Usage,digitalSignature+keyAgreement,digitalSignature+keyAgreement,PASS,
PKI-010,Client Cert,EKU,clientAuth,clientAuth,PASS,
PKI-011,Chain Verification,Leaf→Intermediate→Root,Valid chain,Valid chain,PASS,
PKI-012,Chain Verification,Expired cert rejected,Rejected,Rejected,PASS,
PKI-013,Chain Verification,Wrong EKU rejected,Rejected,Rejected,PASS,
PKI-014,Revocation,CRL includes revoked cert,Listed,Listed,PASS,
PKI-015,Revocation,OCSP returns revoked,revoked,revoked,PASS,
PKI-016,mTLS,Valid client connects,Success,Success,PASS,
PKI-017,mTLS,Revoked client rejected,Rejected,Rejected,PASS,
PKI-018,mTLS,No client cert rejected,Rejected,Rejected,PASS,
```

---

## Grading Rubric (GitHub Actions)

| Criterion | Points |
|-----------|--------|
| Root CA: Self-signed, correct extensions | 10 |
| Intermediate CA: Signed by Root, correct extensions | 10 |
| Server Cert: Key Usage, EKU, SAN correct | 10 |
| Client Certs: Key Usage, EKU, SAN correct | 10 |
| Chain Verification: All validation checks pass | 15 |
| CRL: Generated, signed, includes revoked cert | 10 |
| OCSP: Responder returns correct status | 10 |
| mTLS: Valid client connects, revoked rejected | 15 |
| Findings CSV complete | 10 |
| **Total** | **100** |

---

## Resources

- **RFC 5280**: PKIX Certificate Profile
- **RFC 6960**: OCSP
- **cryptography.io x509**: https://cryptography.io/en/latest/x509/
- **OpenSSL CA tutorial**: https://www.openssl.org/docs/man3.0/man1/ca.html

---

## Academic Integrity

- ☐ **No sharing keys or certificates** — independent generation
- ☐ **Writeups in your own words**
- ☐ **Scope**: Only this lab environment
- ☐ **Violations** → zero for lab + disciplinary referral