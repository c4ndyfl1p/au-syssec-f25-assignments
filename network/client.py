from scapy.all import *
from aes_crypto import encrypt_data, decrypt_data
import base64
# Prompt user for destination IP
dest_ip = input("Enter the destination IP address: ")

password = "my_secure_password"
raw_data = b"hello, CLIENT: secret data"

# Encrypt the raw data
encrypted_data = encrypt_data(raw_data.decode(), password)  # Encoding bytes to string before encryption
encrypted_bytes = base64.b64encode(str(encrypted_data).encode())

pingr = IP(dst=dest_ip)/ICMP(type=47) / Raw(load=encrypted_bytes)

reply= send(pingr)
# print(reply.summary())
# print(reply.show())

