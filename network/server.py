from scapy.all import *
from datetime import datetime
from aes_crypto import encrypt_data, decrypt_data
import base64

password = "my_secure_password"  # Use the same password for decryption(hardcoded)

def icmp_callback(packet):
    if packet.haslayer("ICMP") and packet["ICMP"].type == 47:
        if packet.haslayer(Raw):
            # print(f"Raw data in ICMP Type 47 packet:{datetime.now()} {packet[Raw].load}")

            encrypted_bytes = packet[Raw].load
            # Decode the Base64-encoded encrypted data
            decoded_encrypted_data = base64.b64decode(encrypted_bytes).decode()
        
            # Extract the original encrypted message from the string (it's a dict in string form)
            encrypted_data_dict = eval(decoded_encrypted_data)  # Convert the string representation of dict to actual dict
                
            
            decrypted_data = decrypt_data(encrypted_data_dict, password)

            print(f"Decrypted data: {decrypted_data.encode()}")
            # print(f"ICMP Packet: {packet.summary()}")
                
        else:
            print("No raw data in ICMP Type 47 packet")
        # print(f"ICMP Packet: {packet.summary()}")
        # print(f"Packet Details: {packet.show()}")


       
sniff(filter="icmp ", prn=icmp_callback, store=0, iface="lo") 
