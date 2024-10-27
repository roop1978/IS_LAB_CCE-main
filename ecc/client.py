import socket
import os
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization

def generate_keys():
    """Generate an ECC key pair."""
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    """Serialize public key to bytes."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def compute_sha256(data):
    """Compute SHA-256 hash of the given data."""
    return hashlib.sha256(data).digest()

def sign_data(private_key, data_hash):
    """Sign the hash of the data using the private key."""
    return private_key.sign(data_hash, ec.ECDSA(hashes.SHA256()))

def client_program():
    host = '127.0.0.1'
    port = 65432
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))

    # Generate ECC keys
    private_key, public_key = generate_keys()
    client_pub_key_bytes = serialize_public_key(public_key)

    # Send public key to server
    client_socket.send(client_pub_key_bytes)

    # Receive server's public key
    server_pub_key_bytes = client_socket.recv(1024)
    server_public_key = serialization.load_pem_public_key(server_pub_key_bytes, backend=default_backend())

    # Data to be sent
    data = b"Hello, this is a confidential message."

    # Compute hash and sign the data
    data_hash = compute_sha256(data)
    signature = sign_data(private_key, data_hash)

    # Send data, signature, and hash to the server
    message = data + b'|SIGN|' + signature + b'|HASH|' + data_hash
    client_socket.sendall(message)

    print("Data sent to server.")
    client_socket.close()

if __name__ == "__main__":
    client_program()
