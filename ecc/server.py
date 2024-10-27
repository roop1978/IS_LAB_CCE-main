import socket
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def verify_signature(public_key, data_hash, signature):
    """Verify the signature using the public key."""
    try:
        public_key.verify(signature, data_hash, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception as e:
        print("Signature verification failed:", e)
        return False

def compute_sha256(data):
    """Compute SHA-256 hash of the given data."""
    return hashlib.sha256(data).digest()

def server_program():
    host = '127.0.0.1'
    port = 65432
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)

    print(f"Server listening on {host}:{port}")
    conn, addr = server_socket.accept()
    print(f"Connection from {addr}")

    # Receive client's public key
    client_pub_key_bytes = conn.recv(1024)
    client_public_key = serialization.load_pem_public_key(client_pub_key_bytes, backend=default_backend())

    # Send server's public key
    server_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    server_public_key = server_private_key.public_key()
    server_pub_key_bytes = server_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    conn.send(server_pub_key_bytes)

    # Receive data, signature, and hash
    received_data = conn.recv(2048)
    data, signature, data_hash = received_data.split(b'|SIGN|')[0], received_data.split(b'|SIGN|')[1].split(b'|HASH|')[0], received_data.split(b'|HASH|')[1]

    # Compute the hash of the received data
    computed_hash = compute_sha256(data)

    # Verify the signature
    if verify_signature(client_public_key, computed_hash, signature):
        print("Signature verified!")
        print("Received data:", data.decode())
    else:
        print("Signature verification failed!")

    conn.close()
    server_socket.close()

if __name__ == "__main__":
    server_program()
