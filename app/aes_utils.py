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
    tag_test = tag
    return nonce, ciphertext, tag

def decrypt_aes(key, nonce, ciphertext, tag):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    try:
        data = cipher.decrypt_and_verify(ciphertext, tag)
        print("MAC check passed")
        return data.decode('utf-8')
    except ValueError:
        print("MAC check failed")
        raise
