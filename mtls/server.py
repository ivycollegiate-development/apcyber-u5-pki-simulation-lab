#!/usr/bin/env python3
"""
mTLS Server for PKI Lab
Requires client certificate authentication.
"""
import ssl
import socket
import threading
import os

# Paths to certificates
CA_CERT = "../ca/root_ca/root_ca.crt"
INTERMEDIATE_CERT = "../ca/intermediate_ca/intermediate_ca.crt"
SERVER_CERT = "../ca/certs/server.crt"
SERVER_KEY = "../ca/certs/server.key"

# Combine CA chain for trust store
def create_ca_bundle():
    bundle_path = "ca_bundle.crt"
    with open(bundle_path, "wb") as bundle:
        for ca_file in [CA_CERT, INTERMEDIATE_CERT]:
            with open(ca_file, "rb") as f:
                bundle.write(f.read())
    return bundle_path

def handle_client(conn, addr):
    print(f"[+] Connection from {addr}")
    try:
        # Get client certificate
        cert = conn.getpeercert(binary_form=True)
        if cert:
            from cryptography import x509
            from cryptography.hazmat.primitives.serialization import Encoding
            client_cert = x509.load_der_x509_certificate(cert)
            subject = client_cert.subject.rfc4514_string()
            print(f"    Client certificate: {subject}")
            
            # Check if revoked (simplified - would check CRL/OCSP in production)
            print(f"    Certificate valid, allowing connection")
        else:
            print(f"    No client certificate presented")
            conn.send(b"ERROR: Client certificate required\n")
            return
        
        # Read request
        data = conn.recv(4096)
        print(f"    Received: {data.decode().strip()}")
        
        # Send response
        response = f"Hello {subject}! mTLS connection established securely.\n".encode()
        conn.send(response)
        
    except ssl.SSLError as e:
        print(f"    SSL Error: {e}")
    except Exception as e:
        print(f"    Error: {e}")
    finally:
        conn.close()

def main():
    print("Starting mTLS Server...")
    print("=" * 50)
    
    # Verify files exist
    for f in [CA_CERT, INTERMEDIATE_CERT, SERVER_CERT, SERVER_KEY]:
        if not os.path.exists(f):
            print(f"[!] Missing file: {f}")
            print("Run pki_lab.py first to generate certificates")
            return
    
    ca_bundle = create_ca_bundle()
    print(f"[+] CA Bundle: {ca_bundle}")
    
    # Create SSL context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(SERVER_CERT, SERVER_KEY)
    context.load_verify_locations(ca_bundle)
    context.verify_mode = ssl.CERT_REQUIRED  # Require client cert
    context.check_hostname = False  # We're not verifying hostname
    
    # Create socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', 8443))
    sock.listen(5)
    
    print("[+] Server listening on port 8443 (mTLS required)")
    print("    Waiting for connections...")
    
    try:
        while True:
            conn, addr = sock.accept()
            # Wrap with SSL
            ssl_conn = context.wrap_socket(conn, server_side=True)
            # Handle in thread
            thread = threading.Thread(target=handle_client, args=(ssl_conn, addr))
            thread.daemon = True
            thread.start()
    except KeyboardInterrupt:
        print("\n[*] Shutting down server...")
    finally:
        sock.close()

if __name__ == "__main__":
    main()