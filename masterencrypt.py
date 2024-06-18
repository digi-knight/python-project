from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import os
import base64

# AES Encryption
def aes_encrypt(text, key):
    # Adjust key length to 32 bytes (256 bits)
    key = key.ljust(32, b'\0')[:32]
    
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_text = padder.update(text.encode()) + padder.finalize()

    encrypted_text = encryptor.update(padded_text) + encryptor.finalize()

    return base64.b64encode(iv + encrypted_text).decode('utf-8')

# RSA Encryption
def rsa_encrypt(text, public_key):
    ciphertext = public_key.encrypt(
        text.encode(),
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode('utf-8')

# Load RSA Public Key
def load_rsa_public_key(pem):
    public_key = serialization.load_pem_public_key(
        pem.encode(),
        backend=default_backend()
    )
    return public_key

# Fix base64 padding
def fix_base64_padding(b64_string):
    return b64_string + '==='[len(b64_string) % 4:]

# Main Program
def main():
    print("Choose encryption method (AES/RSA):")
    method = input().strip().upper()

    print("Enter the text to encrypt:")
    text = input()

    if method == 'AES':
        print("Enter the key in base64 (will be adjusted to 32 bytes):")
        key = base64.b64decode(fix_base64_padding(input().strip()))
        try:
            encrypted_text = aes_encrypt(text, key)
            print("Encrypted text (base64 encoded):", encrypted_text)
        except ValueError as e:
            print(e)

    elif method == 'RSA':
        print("Enter the RSA public key in PEM format:")
        pem = input().strip()
        public_key = load_rsa_public_key(pem)
        encrypted_text = rsa_encrypt(text, public_key)
        print("Encrypted text (base64 encoded):", encrypted_text)

    else:
        print("Invalid encryption method.")

if __name__ == "__main__":
    main()
