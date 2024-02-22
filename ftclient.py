
import socket
import sys
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa as rsa, padding as asymmetric_padding
from cryptography.hazmat.primitives import hashes as hashes, padding as symmetric_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def generate_aes_key():
    return os.urandom(32)

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
    if len(sys.argv) != 3:
        print("Incorrect usage")
        print("Correct usage: pyton client.py <server_hostname> <file_save_path>")
        return

    server_hostname = sys.argv[1]
    file_save_path = sys.argv[2]

    TCP_PORT = 60000

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_hostname, TCP_PORT))

    server_public_key_bytes = client_socket.recv(4096)
    server_public_key = serialization.load_pem_public_key(
        server_public_key_bytes,
        backend=default_backend()
    )

    aes_key = generate_aes_key()

    encrypted_aes_key = rsa_encrypt(aes_key, server_public_key)
    client_socket.sendall(encrypted_aes_key)

    iv_and_cipher_text = client_socket.recv(4096)
    iv = iv_and_cipher_text[:16]
    cipher_text = iv_and_cipher_text[16:]
    
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_file_data = decryptor.update(cipher_text) + decryptor.finalize()

    unpadder = symmetric_padding.PKCS7(128).unpadder()
    decrypted_file_data = unpadder.update(decrypted_file_data) + unpadder.finalize()

    with open(file_save_path, 'wb') as file:
        file.write(decrypted_file_data)
    
    client_socket.close()

if __name__ == "__main__":
    main()
