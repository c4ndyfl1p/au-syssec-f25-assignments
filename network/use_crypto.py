#test file for sanity checks

from aes_crypto import encrypt_data, decrypt_data
import base64


# Example usage
if __name__ == "__main__":
    password = "my_secure_password"
    raw_data = b"hello, CLIENT: secret data: scapy is nice"  # Raw binary data

    # Encrypt the raw data
    encrypted_data = encrypt_data(raw_data.decode(), password)  # Encoding bytes to string before encryption
    encrypted_bytes = base64.b64encode(str(encrypted_data).encode())
    
    print(f"Encrypted data: {encrypted_bytes}")

    # Decode the Base64-encoded encrypted data
    decoded_encrypted_data = base64.b64decode(encrypted_bytes).decode()
        
    # Extract the original encrypted message from the string (it's a dict in string form)
    encrypted_data_dict = eval(decoded_encrypted_data)  # Convert the string representation of dict to actual dict
        
    password = "my_secure_password"  # Use the same password for decryption
    decrypted_data = decrypt_data(encrypted_data_dict, password)

    # # Decrypt the encrypted data
    # decrypted_data = decrypt_data(encrypted_data, password)

    # Since the original data was in bytes, we'll print it as raw bytes
    print(f"Decrypted data: {decrypted_data.encode()}")
