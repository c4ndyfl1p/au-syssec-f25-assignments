import requests
import sys


# URL of the target website
BASE_URL = "http://127.0.0.1:5000"
# BASE_URL = "https://cbc.syssec.dk"
# Get the authentication cookie

def replace_byte(byteString: bytes, idx: int, newNumber:int ) -> bytes :
    myByteArray = bytearray(byteString)
    myByteArray[idx] = newNumber
    new_bytes = bytes(myByteArray)
    return new_bytes

def make_request(url, cookie) -> requests.Response:
    response = requests.get(url=url, cookies=cookie)      
    return response

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
    auth_token = get_auth_cookie()
    # print(f"Auth Token (hex): {auth_token}")
    print(f"ATTACK: auth_token[hex]: {auth_token}, len:{len(auth_token)}, blocks:{len(auth_token)/32}")
    # auth_token[0] = "a"
    
    # # Convert hex to bytes
    encrypted_token = bytes.fromhex(auth_token)
    print(encrypted_token)
    print(f"ATTACK: auth_token[bytes]: {encrypted_token}, len:{len(encrypted_token)}, blocks:{len(encrypted_token)/16}")

   

    #change byte 1
    # encrypted_token = replace_byte(encrypted_token, len(encrypted_token)-1, 9 )


    # # Step 2: Recover the secret using the padding oracle attack
    # secret = padding_oracle_attack(encrypted_token)
    # print(f"Recovered secret: {secret}")

    # # Step 3: Forge a valid authentication token
    # forged_token = forge_token(secret)
    # print(f"Forged Token: {forged_token.hex()}")

    # # Step 4: Send the forged token to the server to retrieve a quote
    # cookies = {'authtoken': encrypted_token.hex()}

    for i in range(256):
        encrypted_token = replace_byte(encrypted_token, len(encrypted_token)-1, i )        
        response = make_request(f"{BASE_URL}/quote/", {'authtoken': auth_token})
        if response.text == "No quote for you!":
            padding = "correct"
            print(f"padding is valid at index= __, i={i}, byte={i.to_bytes()}")
            print(f"encrypted_token = {encrypted_token}")
            break     

    
    


    
if __name__ == "__main__":
    main()
