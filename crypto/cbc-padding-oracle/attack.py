import requests
import sys


# URL of the target website
BASE_URL = "http://127.0.0.1:5000"
# BASE_URL = "https://cbc.syssec.dk"
# Get the authentication cookie
blocklength=16

response_messages = ["PKCS#7 padding is incorrect.", "Padding is incorrect.","No quote for you!" ]


def replace_byte(byteString: bytes, idx: int, newNumber:int ) -> bytes :
    """
    """
    myByteArray = bytearray(byteString)
    myByteArray[idx] = newNumber
    new_bytes = bytes(myByteArray)
    return new_bytes

def make_request(url, cookie) -> requests.Response:
    response = requests.get(url=url, cookies=cookie)      
    return response

def find_nth_byte_of_modified_CT(byte_index_to_replace:int ,  attack_ct:bytes, wrong_i:int) -> int:       
    # find nth byte of modified CT such that N+16 th byte of PT would be 0
    for i in range(0,256):        
        attack_ct = replace_byte(attack_ct, byte_index_to_replace, i ) #replace the n_th byte
        
        
        response = make_request(f"{BASE_URL}/quote/", {'authtoken': attack_ct.hex()})
        print(response.text)
        if response.text not in response_messages:
            
            print(f"found_modified_ID: {attack_ct}")
            padding = "correct"
            #handle_edge case if it's the last byte
            print(f"ATTACK_main: padding is valid at byte_number={byte_index_to_replace}, i={i}, byte={i.to_bytes()}")
            print(f"ATTACK_main: when attack CT byte number={byte_index_to_replace} is : i={i} OR byte={i.to_bytes()}, plaintext byte {byte_index_to_replace+ 16} is 0x__(ie valid padding)")
            # print(f"ATTACK_main: auth_token[bytes]: {original_token}, len:{len(original_token)}, blocks:{len(original_token)/16}")
            return i

#=============================================

def get_auth_cookie():
    response = requests.get(f"{BASE_URL}/")
    if 'authtoken' in response.cookies:
        return response.cookies['authtoken']
    else:
        print("Failed to get auth token!")
        sys.exit(1)


# Padding oracle attack to decrypt the token
def padding_oracle_attack(encrypted_token):
    # Implement CBC padding oracle attack to recover the secret
    pass  # Replace this with your attack logic

# Forge a valid authentication token
def forge_token(secret):
    # Implement CBC encryption using the oracle to generate a valid token
    pass  # Replace this with your attack logic

def main():
    # Step 1: Get the authentication cookie
    # auth_token = get_auth_cookie()
    # print(f"Auth Token (hex): {auth_token}")
    auth_token = "ed7a9373de4e741aefde1e88c48cd930259f977e870809d516deea23cdf1f327a0885b603c6b6d021ef4fb5a363f38ac921d55282a936bfdc468cf60f32e9338"
    print(f"ATTACK: auth_token[hex]: {auth_token}, len:{len(auth_token)}, blocks:{len(auth_token)/32}\n")
    # auth_token[0] = "a"
    
    # # Convert hex to bytes
    original_token = bytes.fromhex(auth_token)
    
    print(original_token)
    print(f"ATTACK: auth_token[bytes]: {original_token}, len:{len(original_token)}, blocks:{len(original_token)/16}\n")

   

    #change byte 1
    # encrypted_token = replace_byte(encrypted_token, len(encrypted_token)-1, 9 )


    #=========== manual mode 
    # for p63 
    print(f"original token 47 is {original_token[47]}\n")

    attack_ct = original_token[:]
    c_47_x = find_nth_byte_of_modified_CT(47, attack_ct, original_token[47])
    

    y_63 = 0x01 ^ c_47_x
    print(y_63.to_bytes())
    print(f"original token 47 is {original_token[47]}")
    p_63 = original_token[47] ^ y_63   
    print(p_63.to_bytes())

    # for p62

    attack_ct = original_token[:]
    
      

   
                



    
if __name__ == "__main__":
    main()
