# aes_utils.py
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

def generate_aes_key():
    return get_random_bytes(16)

tag_test = b""  # Initialize global variable

def encrypt_aes(key, data):
    global tag_test  # Declare tag_test as global
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
    # print("original tag:", tag, type(tag))
    tag_test = tag
    return nonce, ciphertext, tag

def decrypt_aes(key, nonce, ciphertext, tag):
    # print("Decryption - key:", key)
    # print("Decryption - nonce:", nonce, type(nonce))
    # print("Decryption - ciphertext:", ciphertext, type(ciphertext))
    # print("Decryption - tag:", tag, type(tag))
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    try:
        data = cipher.decrypt_and_verify(ciphertext, tag)
        print("MAC check passed")
        return data.decode('utf-8')
    except ValueError:
        print("MAC check failed")
        raise

if __name__ == "__main__":
    key = generate_aes_key()
    data = "test data"
    nonce, ciphertext, tag = encrypt_aes(key, data)

    # For testing, decode and encode again to simulate storage and retrieval
    nonce_b64 = base64.b64encode(nonce).decode('utf-8')
    ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')
    tag_b64 = base64.b64encode(tag).decode('utf-8')

    nonce = base64.b64decode(nonce_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    tag = base64.b64decode(tag_b64)

    decrypted_data = decrypt_aes(key, nonce, ciphertext, tag)
    print("Decrypted data:", decrypted_data)