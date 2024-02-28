
import socket
import sys
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa as rsa, padding as asymmetric_padding
from cryptography.hazmat.primitives import hashes as hashes, padding as symmetric_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

TCP_PORT = 60000
AES_KEY_SIZE = 32
IV_SIZE = 16

def generate_iv():
    return os.urandom(IV_SIZE)

def rsa_decrypt(cipher_text, private_key):
    plain_text = private_key.decrypt(
        cipher_text, 
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plain_text

def main():
    if len(sys.argv) != 2:
        print("Incorrect usage")
        print("Correct usage: python server.py <file_path>")
        return
    
    file_path = sys.argv[1]

    # Initialization vector
    iv = generate_iv()

    # Generate private and public key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # To bytes
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Setup and listen on socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', TCP_PORT))
    server_socket.listen(1)
    print(f"Server is listening on port {TCP_PORT}...")

    # Accept connection from client
    client_socket, client_address = server_socket.accept()
    print(f"Connection established with {client_address}")

    # Send public key in bytes
    client_socket.sendall(public_key_bytes)

    # Receive and decrypt the AES key
    encrypted_aes_key = client_socket.recv(4096)
    aes_key = rsa_decrypt(encrypted_aes_key, private_key)

    # Find the file to send in plain text and encrypt it with the AES key and
    # initialization vector to cipher text
    with open(file_path, 'rb') as file:
        file_data = file.read()

        padder = symmetric_padding.PKCS7(128).padder()
        padded_data = padder.update(file_data) + padder.finalize()

        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        cipher_text = encryptor.update(padded_data) + encryptor.finalize()
        client_socket.sendall(iv + cipher_text)
    
    client_socket.close()
    server_socket.close()

if __name__ == "__main__":
    main()