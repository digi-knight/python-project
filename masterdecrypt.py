from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import base64

# AES Decryption
def aes_decrypt(encrypted_text, key):
    # Adjust key length to 32 bytes (256 bits)
    key = key.ljust(32, b'\0')[:32]
    
    encrypted_text = base64.b64decode(fix_base64_padding(encrypted_text))
    iv = encrypted_text[:16]
    encrypted_text = encrypted_text[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_text = decryptor.update(encrypted_text) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    text = unpadder.update(padded_text) + unpadder.finalize()

    return text.decode()

# RSA Decryption
def rsa_decrypt(encrypted_text, private_key):
    ciphertext = base64.b64decode(fix_base64_padding(encrypted_text))
    plaintext = private_key.decrypt(
        ciphertext,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()

# Load RSA Private Key
def load_rsa_private_key(pem, password=None):
    private_key = serialization.load_pem_private_key(
        pem.encode(),
        password=password,
        backend=default_backend()
    )
    return private_key

# Fix base64 padding
def fix_base64_padding(b64_string):
    return b64_string + '==='[len(b64_string) % 4:]

# Main Program
def main():
    print("Choose decryption method (AES/RSA):")
    method = input().strip().upper()

    print("Enter the text to decrypt (base64 encoded):")
    encrypted_text = input().strip()

    if method == 'AES':
        print("Enter the key in base64 (will be adjusted to 32 bytes):")
        key = base64.b64decode(fix_base64_padding(input().strip()))
        try:
            decrypted_text = aes_decrypt(encrypted_text, key)
            print("Decrypted text:", decrypted_text)
        except ValueError as e:
            print(e)

    elif method == 'RSA':
        print("Enter the RSA private key in PEM format:")
        pem = input().strip()
        private_key = load_rsa_private_key(pem)
        decrypted_text = rsa_decrypt(encrypted_text, private_key)
        print("Decrypted text:", decrypted_text)

    else:
        print("Invalid decryption method.")

if __name__ == "__main__":
    main()
