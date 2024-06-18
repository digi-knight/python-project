from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2


def generate_key(password):
  """
  Generates a secure key from a password using PBKDF2.

  Args:
      password: The user's password (string)

  Returns:
      A byte string containing the derived key
  """
  salt = get_random_bytes(16)  # Generate random salt for key derivation
  kdf = PBKDF2(password, salt, dkLen=32, count=100000, hmac_hash_module='sha256')
  return kdf


def encrypt_message(message, password):
  """
  Encrypts a message using AES-GCM and returns the encrypted data.

  Args:
      message: The message to encrypt (string)
      password: The user's password for key derivation

  Returns:
      A byte string containing the encrypted data (ciphertext + tag + nonce)
  """
  data = message.encode("utf-8")
  key = generate_key(password)  # Generate key from password
  cipher = AES.new(key, AES.MODE_GCM)
  nonce = get_random_bytes(12)
  ciphertext, tag = cipher.encrypt_and_digest(data)
  encrypted_data = ciphertext + tag + nonce
  return encrypted_data


def decrypt_message(encrypted_data, password):
  """
  Decrypts encrypted data using AES-GCM and returns the original message.

  Args:
      encrypted_data: The encrypted data (ciphertext + tag + nonce)
      password: The user's password for key derivation

  Returns:
      The decrypted message (string) on success, None on errors
  """
  try:
    key = generate_key(password)  # Generate key from password
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag, nonce = encrypted_data[:-32], encrypted_data[-16:-12], encrypted_data[-12:]
    output = bytearray(len(ciphertext))
    plaintext = cipher.decrypt_and_verify(ciphertext, tag, nonce, output=output)
    return plaintext.decode("utf-8")
  except (ValueError, KeyError):
    # Handle decryption errors (e.g., invalid key or corrupt data)
    print("Decryption error!")
    return None


# Get user input for the message and password
message = input("Enter your message to encrypt: ")
password = input("Enter your password: ")

# Encrypt the message
encrypted_data = encrypt_message(message, password)

# Print the encrypted data in hexadecimal format
print("Encrypted data (hex):", encrypted_data.hex())

# Decrypt the message
decrypted_message = decrypt_message(encrypted_data, password)

if decrypted_message:
  print("Decrypted message:", decrypted_message)
else:
  print("Decryption failed!")
