
import socket
import sys
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa as rsa, padding as asymmetric_padding
from cryptography.hazmat.primitives import hashes as hashes, padding as symmetric_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

TCP_PORT = 12345
AES_KEY_SIZE = 32
IV_SIZE = 16

def generate_aes_key():
    return os.urandom(AES_KEY_SIZE)

def generate_iv():
    return os.urandom(IV_SIZE)

def rsa_encrypt(message, public_key):
    cipher_text = public_key.encrypt(
        message,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return cipher_text

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
        print("Incorrect usage: python server.py <file_path>")
        return
    
    file_path = sys.argv[1]

    aes_key = generate_aes_key()
    iv = generate_iv()

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', TCP_PORT))
    server_socket.listen(1)
    print(f"Server is listening on port {TCP_PORT}...")

    client_socket, client_address = server_socket.accept()
    print(f"Connection established with {client_address}")

    client_socket.sendall(public_key_bytes)

    encrypted_aes_key = client_socket.recv(4096)
    aes_key = rsa_decrypt(encrypted_aes_key, private_key)

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