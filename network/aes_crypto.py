from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
import base64

# Function to generate a key from a password using scrypt (for key derivation)
def generate_key(password: str, salt: bytes) -> bytes:
    key = scrypt(password.encode(), salt, key_len=32, N=2**14, r=8, p=1)  # AES-256
    return key

# Function to encrypt data using AES-GCM
def encrypt_data(data: str, password: str) -> dict:
    # Generate a random salt and initialization vector (IV)
    salt = get_random_bytes(16)
    iv = get_random_bytes(12)  # AES-GCM typically uses a 12-byte IV

    # Derive the key from the password
    key = generate_key(password, salt)

    # Create an AES cipher object using AES-GCM mode
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)

    # Encrypt the data and get the ciphertext and tag
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())

    # Return the encrypted data along with IV, salt, and tag (necessary for decryption)
    return {
        'ciphertext': base64.b64encode(ciphertext).decode(),
        'iv': base64.b64encode(iv).decode(),
        'salt': base64.b64encode(salt).decode(),
        'tag': base64.b64encode(tag).decode()
    }

# Function to decrypt data using AES-GCM
def decrypt_data(encrypted_data: dict, password: str) -> str:
    # Decode the data from base64 encoding
    ciphertext = base64.b64decode(encrypted_data['ciphertext'])
    iv = base64.b64decode(encrypted_data['iv'])
    salt = base64.b64decode(encrypted_data['salt'])
    tag = base64.b64decode(encrypted_data['tag'])

    # Derive the key from the password using the same salt
    key = generate_key(password, salt)

    # Create an AES cipher object using AES-GCM mode
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)

    # Decrypt the data
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    return plaintext.decode()
