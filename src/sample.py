'''
This code is from the pycryptodome documentation.
It was used to learn how to use the encryption/decryption module
https://pycryptodome.readthedocs.io/en/latest/src/examples.html
'''

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key = get_random_bytes(16)
data = b"The quick brown fox jumped over the fence"
print(data)
nonce = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
ciphertext, tag = cipher.encrypt_and_digest(data)

file_out = open("encrypted.bin", "wb")
for x in (cipher.nonce, tag, ciphertext):
    file_out.write(x)
file_out.close()

file_in = open("encrypted.bin", "rb")

nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]

# let's assume that the key is somehow available again
cipher = AES.new(key, AES.MODE_EAX, nonce)
data = cipher.decrypt_and_verify(ciphertext, tag)
print(data)
