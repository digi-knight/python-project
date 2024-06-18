from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Define the data to encrypt
data = "This is a secret message!".encode("utf-8")

# Generate a strong random key (128-bit key)
key = get_random_bytes(16)  # Replace with your own secure key generation method

# Create an AES cipher object
cipher = AES.new(key, AES.MODE_EAX)

# Generate a random initialization vector (IV)
ciphertext, iv = cipher.encrypt_and_digest(data)

# Print the encrypted data (ciphertext) and initialization vector (IV) in hexadecimal format
print("Encrypted data (hex):", ciphertext.hex())
print("Initialization Vector (IV) (hex):", iv.hex())
