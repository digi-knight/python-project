from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def encrypt_message(message):
  """
  Encrypts a message using AES-GCM and returns the encrypted data.

  Args:
      message: The message to encrypt (string)

  Returns:
      A byte string containing the encrypted data (ciphertext + tag + nonce)
  """
  # Encode message to bytes
  data = message.encode("utf-8")

  # Generate a strong random key (128-bit key)
  key = get_random_bytes(16)  # Replace with secure key generation in real use

  # Create an AES cipher object (recommended mode: GCM)
  cipher = AES.new(key, AES.MODE_GCM)

  # Generate a random nonce
  nonce = get_random_bytes(12)

  # Encryption with authentication
  ciphertext, tag = cipher.encrypt_and_digest(data)

  # Combine ciphertext, tag, and nonce for decryption
  encrypted_data = ciphertext + tag + nonce

  return encrypted_data

# Get user input for the message
message = input("Enter your message to encrypt: ")

# Encrypt the message
encrypted_data = encrypt_message(message)

# Print the encrypted data in hexadecimal format
print("Encrypted data (hex):", encrypted_data.hex())
