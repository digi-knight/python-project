from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import base64

def adjust_key(key):
    # Adjust key to be 32 bytes long (256 bits) by padding with zeros or truncating
    if len(key) < 32:
        key = key.ljust(32, b'\0')  # Pad with null bytes
    elif len(key) > 32:
        key = key[:32]  # Truncate to 32 bytes
    return key

def encrypt(text, key):
    key = adjust_key(key)

    # Generate a random 16-byte IV
    iv = os.urandom(16)

    # Create a Cipher object using the key and IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad the text to be a multiple of the block size (16 bytes for AES)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_text = padder.update(text.encode()) + padder.finalize()

    # Encrypt the padded text
    encrypted_text = encryptor.update(padded_text) + encryptor.finalize()

    # Return the IV and the encrypted text encoded in base64
    return base64.b64encode(iv + encrypted_text).decode('utf-8')

# Get user input for text and key
text = input("Enter the text to encrypt: ")
key = input("Enter the key: ").encode()

encrypted_text = encrypt(text, key)
print("Encrypted text (base64 encoded):", encrypted_text)
