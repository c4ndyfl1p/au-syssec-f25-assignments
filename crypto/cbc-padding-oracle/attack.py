import requests
import sys


# URL of the target website
BASE_URL = "http://127.0.0.1:5000"
# BASE_URL = "https://cbc.syssec.dk"
# Get the authentication cookie
blocklength=16

response_messages = ["PKCS#7 padding is incorrect.", "Padding is incorrect.","No quote for you!" ]

class PaddingOracleException(Exception):
    """Custom exception raised when valid padding is not found."""
    pass


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
        #print(response.text)
        if response.text not in response_messages:
            
            print(f"found_modified_ID: {attack_ct}")
            padding = "correct"
            #handle_edge case if it's the last byte
            print(f"ATTACK_main: padding is valid at byte_number={byte_index_to_replace}, i={i}, byte={i.to_bytes()}")
            print(f"ATTACK_main: when attack CT byte number={byte_index_to_replace} is : i={i} OR byte={i.to_bytes()}, plaintext byte {byte_index_to_replace+ 16} is 0x__(ie valid padding)")
            # print(f"ATTACK_main: auth_token[bytes]: {original_token}, len:{len(original_token)}, blocks:{len(original_token)/16}")
            return i

    # If no valid padding was found, raise an exception
    raise PaddingOracleException(f"No valid padding found for byte index {byte_index_to_replace}")

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
    auth_token = "28e597392e7d4c765ec436d2a6dcc6feee2caa69120dd9824e091f70f3c76619cc4fe84c4a2756d619ed117a8319719487174dd61ee3eb90fe1e163d5e12521b"
    print(f"ATTACK: auth_token[hex]: {auth_token}, len:{len(auth_token)}, blocks:{len(auth_token)/32}\n")
    
    
    # # Convert hex to bytes
    original_token = bytes.fromhex(auth_token)
    
    print(original_token)
    print(f"ATTACK: auth_token[bytes]: {original_token}, len:{len(original_token)}, blocks:{len(original_token)/16}\n")
    no_of_blocks = len(original_token)/16
   

    #change byte 1
    # encrypted_token = replace_byte(encrypted_token, len(encrypted_token)-1, 9 )


    #=========== manual mode 
    # for p63 

    # i = 1
    
    # n = 3
    # idx = (blocklength * n) -i # 47

    # decrypted_plaintext = bytes(len(original_token))
    # ct_x = bytes(len(original_token))
    # print(f"original token 47={idx} is {original_token[idx]}\n")

    # attack_ct = original_token[:]
    # c_47_x = find_nth_byte_of_modified_CT(idx, attack_ct, original_token[idx])
    # ct_x = replace_byte(ct_x, idx, c_47_x)

    # y_63 = i ^ c_47_x
    # print(y_63.to_bytes())
    # print(f"original token 47 is {original_token[idx]}")
    # p_63 = original_token[idx] ^ y_63   
    # print(p_63.to_bytes())
    # decrypted_plaintext = replace_byte(decrypted_plaintext, idx+16, p_63)

    # # for c46 / p62
    # i = 2
    # idx = (blocklength * n) -i # 46
    # #set ultimate byte to 0x02
    # attack_ct = original_token[:]
    
    # for j in range(1, i):
    #     idx_j = (blocklength*n)-j #47
    #     c_j_x = ct_x[idx_j]
    #     attack_ct = replace_byte(attack_ct, idx_j, c_j_x ^ j^ i) # look at it in a bit

    # #search for c_46_x
    # c_46_x = find_nth_byte_of_modified_CT(idx, attack_ct, 0)
    # y_62 = c_46_x ^ i
    # p_62 = original_token[46] ^ y_62
    # print(p_62.to_bytes())

    # attack_ct = original_token[:]
    # decrypted_plaintext = replace_byte(decrypted_plaintext, idx+16, p_62)

    # print(decrypted_plaintext)
    
    #generic attack for one block when n = 3

    decrypted_plaintext = bytes(len(original_token))
    ct_x = bytes(len(original_token))

    n = 3
    for i in range(1, 17):
        idx = (blocklength * n) -i # 46 #the cT byte index that we will modify
        print(f"i:{i}, idx:{idx}================================================\n")
        
        attack_ct = original_token[:]

        #replace previous(bits ahead) bits(if applicable) with the zeroing ct ^ i
        for j in range(1, i):
            idx_j = (blocklength*n)-j #47
            c_j_x = ct_x[idx_j] #extract the found ct byte that results in valid padding at byte+16
            attack_ct = replace_byte(attack_ct, idx_j, c_j_x ^ j^ i) # look at it in a bit

        print(f"attack ct: {attack_ct}")
        
        # Find the current byte that produces valid padding
        c_46_x = find_nth_byte_of_modified_CT(idx, attack_ct, 0)
        print(c_46_x)

        # Update ct_x for bookkeeping
        ct_x = replace_byte(ct_x, idx, c_46_x) #bookkeeping

        # Compute y_62 (the keystream byte)
        y_62 = c_46_x ^ i
        p_62 = original_token[idx] ^ y_62
        print(p_62.to_bytes())

        # Update decrypted plaintext with the found byte
        decrypted_plaintext = replace_byte(decrypted_plaintext, idx+16, p_62) #bookkeeping

        
    
        



    
if __name__ == "__main__":
    main()
