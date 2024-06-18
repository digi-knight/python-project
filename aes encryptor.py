from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64

def adjust_key(key):
    # Adjust key to be 32 bytes long (256 bits) by padding with zeros or truncating
    if len(key) < 32:
        key = key.ljust(32, b'\0')  # Pad with null bytes
    elif len(key) > 32:
        key = key[:32]  # Truncate to 32 bytes
    return key

def decrypt(encrypted_text, key):
    key = adjust_key(key)

    # Decode the base64 encoded encrypted text
    encrypted_text = base64.b64decode(encrypted_text)

    # Extract the IV from the beginning of the encrypted text
    iv = encrypted_text[:16]
    encrypted_text = encrypted_text[16:]

    # Create a Cipher object using the key and IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the encrypted text
    padded_text = decryptor.update(encrypted_text) + decryptor.finalize()

    # Unpad the decrypted text
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    text = unpadder.update(padded_text) + unpadder.finalize()

    return text.decode()

# Get user input for encrypted text and key
encrypted_text = input("Enter the encrypted text (base64 encoded): ")
key = input("Enter the key: ").encode()

try:
    decrypted_text = decrypt(encrypted_text, key)
    print("Decrypted text:", decrypted_text)
except ValueError as e:
    print(e)
