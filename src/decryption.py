from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import base64

def decrypt_aes(ciphertext, key):
    raw_data = base64.b64decode(ciphertext)
    nonce = raw_data[:16]
    ciphertext = raw_data[16:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode('utf-8')

def decrypt_rsa(ciphertext, private_key):
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    raw_data = base64.b64decode(ciphertext)
    plaintext = cipher.decrypt(raw_data)
    return plaintext.decode('utf-8')