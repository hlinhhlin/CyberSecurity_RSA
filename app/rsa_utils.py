# rsa_utils.py
from Crypto.Util import number
import random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import base64

#generate key pair
def generate_keypair(bits=2048):
    p = number.getPrime(bits // 2)
    q = number.getPrime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = random.randrange(1, phi)
    g = number.GCD(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = number.GCD(e, phi)
    d = number.inverse(e, phi)
    return ((e, n), (d, n))

def encrypt_rsa(public_key, plaintext):
    e, n = public_key
    plaintext_bytes = plaintext.encode('utf-8')
    plaintext_int = int.from_bytes(plaintext_bytes, byteorder='big')
    ciphertext = pow(plaintext_int, e, n)
    return ciphertext

def decrypt_rsa(private_key, ciphertext):
    d, n = private_key
    plaintext_int = pow(ciphertext, d, n)
    plaintext_bytes = plaintext_int.to_bytes((plaintext_int.bit_length() + 7) // 8, byteorder='big')
    plaintext = plaintext_bytes.decode('utf-8', errors='ignore')  # Ignore errors for non-textual data
    return plaintext

# # Encrypt AES key with RSA public key
# def encrypt_aes_key_with_rsa(aes_key, rsa_public_key):
#     cipher_rsa = PKCS1_OAEP.new(RSA.import_key(rsa_public_key))
#     encrypted_aes_key = cipher_rsa.encrypt(aes_key)
#     return base64.b64encode(encrypted_aes_key).decode('utf-8')

# # Decrypt AES key with RSA private key
# def decrypt_aes_key_with_rsa(encrypted_aes_key, rsa_private_key):
#     cipher_rsa = PKCS1_OAEP.new(RSA.import_key(rsa_private_key))
#     decoded_encrypted_aes_key = base64.b64decode(encrypted_aes_key)
#     aes_key = cipher_rsa.decrypt(decoded_encrypted_aes_key)
#     return aes_key