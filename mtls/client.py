#!/usr/bin/env python3
"""
mTLS Client for PKI Lab
Connects to mTLS server with client certificate.
"""
import ssl
import socket
import sys
import os

# Paths (relative to mtls/ directory)
CA_CERT = "../ca/root_ca/root_ca.crt"
INTERMEDIATE_CERT = "../ca/intermediate_ca/intermediate_ca.crt"

def create_ca_bundle():
    bundle_path = "ca_bundle.crt"
    with open(bundle_path, "wb") as bundle:
        for ca_file in [CA_CERT, INTERMEDIATE_CERT]:
            with open(ca_file, "rb") as f:
                bundle.write(f.read())
    return bundle_path

def connect_with_client_cert(client_cert_path, client_key_path, message="Hello from mTLS client!"):
    """Connect to mTLS server using specified client certificate."""
    
    if not os.path.exists(client_cert_path) or not os.path.exists(client_key_path):
        print(f"[!] Client certificate/key not found:")
        print(f"    Cert: {client_cert_path} ({'exists' if os.path.exists(client_cert_path) else 'MISSING'})")
        print(f"    Key:  {client_key_path} ({'exists' if os.path.exists(client_key_path) else 'MISSING'})")
        return False
    
    ca_bundle = create_ca_bundle()
    
    # Create SSL context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(ca_bundle)
    context.load_cert_chain(client_cert_path, client_key_path)
    context.check_hostname = False  # Not verifying hostname for localhost
    context.verify_mode = ssl.CERT_REQUIRED
    
    try:
        print(f"[*] Connecting to server with {client_cert_path}...")
        
        sock = socket.create_connection(('localhost', 8443))
        ssl_sock = context.wrap_socket(sock, server_hostname='localhost')
        
        # Verify server certificate
        server_cert = ssl_sock.getpeercert(binary_form=True)
        if server_cert:
            from cryptography import x509
            server_cert_obj = x509.load_der_x509_certificate(server_cert)
            print(f"[+] Server certificate: {server_cert_obj.subject.rfc4514_string()}")
            print(f"    Issuer: {server_cert_obj.issuer.rfc4514_string()}")
        
        # Send message
        ssl_sock.send(message.encode())
        
        # Receive response
        response = ssl_sock.recv(4096)
        print(f"[+] Server response: {response.decode().strip()}")
        
        ssl_sock.close()
        return True
        
    except ssl.SSLError as e:
        print(f"[!] SSL Error: {e}")
        return False
    except ConnectionRefusedError:
        print(f"[!] Connection refused - is server running on port 8443?")
        return False
    except Exception as e:
        print(f"[!] Error: {e}")
        return False

def main():
    print("mTLS Client for PKI Lab")
    print("=" * 50)
    
    # Test clients
    clients = [
        ("client_alice", "Alice (valid)"),
        ("client_bob", "Bob (valid)"),
        ("client_revoked", "Revoked User (should be rejected by CRL/OCSP check)"),
    ]
    
    for cert_name, description in clients:
        print(f"\n--- Testing: {description} ---")
        cert_path = f"../ca/certs/{cert_name}.crt"
        key_path = f"../ca/certs/{cert_name}.key"
        
        success = connect_with_client_cert(cert_path, key_path)
        if success:
            print(f"    Result: CONNECTED")
        else:
            print(f"    Result: REJECTED/FAILED")
    
    print("\n" + "=" * 50)
    print("Note: Server does CRL/OCSP check in production.")
    print("For this lab, server accepts any valid cert signed by our CA.")
    print("Revocation checking would be implemented in server.py")

if __name__ == "__main__":
    main()