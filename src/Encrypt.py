'''
Created 3/4/2020
@author: joanne-li

Some docs for reference
https://pycryptodome.readthedocs.io/en/latest/src/examples.html

NOTE: Change line 210 of /hash/CMAC.py file partial --> bytes()
'''
import hashlib
import json
from datetime import datetime
from Crypto.Cipher import AES # https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html
from Crypto.Random import get_random_bytes

class Encrypt():
    # saltlen = 16. Increase to increase complexity
    # iterations = 100000. Increase iterations to slow attacks
    def __init__(self, saltlen=16,iterations=100000):
        self._saltlen = saltlen
        self._iterations = iterations

    # Encrypts important user information.
    # The key (fileKey) used to encrypt the password file, is encrypted here
    # The user's password is used to generate a key to help encrypt the fileKey
    def encrypt_user_info(self, username, password, fileKey):
        salt = get_random_bytes(self._saltlen)
        derivedKey, authKey = self.derive_key_pass(password,salt)

        # Encrypt fileKey, with derivedKey and initialisation vector
        IV = get_random_bytes(16)
        cipherObj = AES.new(derivedKey, AES.MODE_EAX, nonce=IV)

        # Verifytag is a MAC used to verify that the key on file has not been modified by an attacker
        obscKey, verifyTag = cipherObj.encrypt_and_digest(fileKey) # fileKey now encrypted as obscKey
        # Encrypt username
        hashedUsername = hashlib.pbkdf2_hmac('sha256', username, salt, self._iterations, dklen=16)

        with open('stored_cred.bin', 'wb') as storedCred:
            [storedCred.write(i) for i in (salt, IV, authKey, obscKey, verifyTag, hashedUsername)]

    # Decrypt ciphertext
    # Use cases:
    # - decrypt key used to encrypt password file
    # - decrypt password file
    def decrypt_ciphertext(self, key, ciphertext, nonce, tag):
        cipherObj = AES.new(key, AES.MODE_EAX, nonce)
        data = cipherObj.decrypt_and_verify(ciphertext, tag)
        return data

    # ==========================================================================
    # Passfile operations
    # Verify login attempt or verify password to change master password
    def verify_login(self, username, password):
        if type(password) is str: password = password.encode('utf-8')
        if type(username) is str: username = username.encode('utf-8')
        derivedKey, authKey = self.derive_key_pass(password, self.get_salt())

        derivedUsername = hashlib.pbkdf2_hmac('sha256', username, self.get_salt(), self._iterations, dklen=16)
        return (authKey == self.get_authKey()) and (derivedUsername == self.get_username())


    # filekey encrypts the passfile
    # passfile: unencrypted python dictionary
    def encrypt_pass(self, filekey, passfile):
        passfile = json.dumps(passfile).encode('utf-8')
        IV = get_random_bytes(16)
        cipherObj = AES.new(filekey, AES.MODE_EAX, nonce=IV)
        obscPass, verifyTag = cipherObj.encrypt_and_digest(passfile)

        with open('passfile.bin', 'wb') as passfile:
            [passfile.write(i) for i in (IV, verifyTag, obscPass)]

    def derive_filekey(self, masterpassword):
        dkey, authKey = self.derive_key_pass(masterpassword, self.get_salt())
        passwordFileKey = self.decrypt_ciphertext(dkey, self.get_obsc_key(), self.get_IV(), self.get_tag())
        return passwordFileKey

    # Derives two keys from given password and salt
    # derivedKey = key used to encrypt password file key
    # authKey = key used to verify password has been inputted correctly
    def derive_key_pass(self, password, salt):
        resKey = hashlib.pbkdf2_hmac('sha256', password, salt, self._iterations, dklen=32)

        # derivedKey is used to encrypt the password file key
        derivedKey = resKey[:16]
        # AuthKey is used to check if the user has entered the correct password on login
        authKey = derivedKey[-16:]
        return (derivedKey, authKey)

    # Get passfile
    def decrypt_passfile(self, masterpassword):
        dkey, authKey = self.derive_key_pass(masterpassword, self.get_salt())
        if authKey == self.get_authKey():
            passwordFileKey = self.decrypt_ciphertext(dkey, self.get_obsc_key(), self.get_IV(), self.get_tag())
            tag = self.get_tag('passfile.bin', 16)
            decryptedPassFile = self.decrypt_ciphertext(passwordFileKey, self.get_passfile(), self.get_IV('passfile.bin', 0), tag)
            return self.passfile_dict(decryptedPassFile)

    def get_passfile(self):
        with open('passfile.bin', 'rb') as f:
            f.seek(32, 1)
            passFile = f.read()
        return passFile

    def passfile_dict(self, passString):
        return json.loads(passString)

    # ==========================================================================
    # Credential operations
    # Get the salt associated with the user's master password
    def get_salt(self):
        with open('stored_cred.bin', 'rb') as f:
            salt = f.read(16)
        return salt

    def get_IV(self, filename='stored_cred.bin', startseek=16):
        with open(filename, 'rb') as f:
            f.seek(startseek, 1) # Start reading after 16th byte
            authKey = f.read(16)
        return authKey

    # Get the authKey for the user
    # Used to authorise the user into system. Password input checked against this
    def get_authKey(self):
        with open('stored_cred.bin', 'rb') as f:
            f.seek(32, 1) # Start reading after 32nd byte
            authKey = f.read(16)
        return authKey

    def get_obsc_key(self,filename='stored_cred.bin', startseek=48):
        with open(filename, 'rb') as f:
            f.seek(startseek, 1) # Start reading after startseek byte
            authKey = f.read(16)
        return authKey

    def get_tag(self, filename='stored_cred.bin', startseek=64):
        with open(filename, 'rb') as f:
            f.seek(startseek, 1) # Start reading after startseek byte
            authKey = f.read(16)
        return authKey

    def get_username(self):
        with open('stored_cred.bin', 'rb') as f:
            f.seek(80, 1) # Start reading after 32nd byte
            authKey = f.read(16)
        return authKey
