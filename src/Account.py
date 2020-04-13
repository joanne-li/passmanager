'''
Add, edit, modify user information and details

Created 4/4/2020
@author: joanne-li
'''
import json
import os
from Encrypt import Encrypt
from Crypto.Random import get_random_bytes

class Account():
    def __init__(self, username, password):
        self._username = username
        self._enc = Encrypt()
        self._masterpassword = self.to_byte_string(password)
        self._passdict = self.get_passfile()

    @property
    def username(self):
        return self._username

    @username.setter
    def username(self, username):
        self._username = username

    # Create a new user account
    def create_account(self, masterpassword):
        password = self.to_byte_string(masterpassword)
        self._masterpassword = password

        # Unencrypted state; key to encrypt passfile
        fileKey = get_random_bytes(16)
        self._enc.encrypt_user_info(self.to_byte_string(self._username), password, fileKey)

        # Create passfile
        # passfile = json.dumps(self._passdict)
        # passfile = self.to_byte_string(passfile)
        self._enc.encrypt_pass(fileKey, self._passdict)
        fileKey = None # Make sure to delete this unencrypted key!


    # Get unencrypted password file dictionary
    def get_passfile(self):
        return self._enc.decrypt_passfile(self._masterpassword)

    def set_passdict(self, passfiledict):
        self._passdict = passfiledict

    def get_passdict(self):
        return self._passdict

    def set_masterpassword(self, password):
        self._masterpassword = self.to_byte_string(password)

    def change_master_pass(self, newMaster):
        newMaster = self.to_byte_string(newMaster)
        # Decrypt passwordFileKey
        dkey, authkey = self._enc.derive_key_pass(self._masterpassword, self._enc.get_salt())
        passwordFileKey = self._enc.decrypt_ciphertext(dkey, self._enc.get_obsc_key(), self._enc.get_IV(), self._enc.get_tag())

        # Encypt passwordFileKey with newMaster
        username = self.to_byte_string(self._username)
        self._enc.encrypt_user_info(username, newMaster, passwordFileKey)
        self._masterpassword = newMaster
        passwordFileKey = None

    # ==========================================================================
    # Manage passwords in the password manager
    # Add account to passfile (dictionary type)
    # username = account username, not the password manager username
    # passdict = {organisation: {username1: pass1, username2: pass2}, organisation2....}
    def add_account(self, organisation, username, password):
        passdict = self._passdict
        if passdict.get(organisation) is None:
            passdict[organisation] = {}
        passdict[organisation][username] = password
        print(passdict)
        self.set_passdict(passdict)

    # Remove account frrom passfile
    def remove_account(self, organisation, username):
        passdict = self._passdict
        del passdict[organisation][username]
        if len(passdict[organisation]) == 0: del passdict[organisation]
        self.set_passdict(passdict)

    # Edit account username
    def edit_acc_username(self, organisation, oldUsername, newUsername):
        passdict = self._passdict
        password = passdict[organisation][oldUsername]
        del passdict[organisation][oldUsername]
        passdict[organisation][newUsername] = password
        self.set_passdict(passdict)

    # Edit account password
    def edit_acc_password(self, organisation, username, password):
        passdict = self._passdict
        print(passdict)
        print(organisation)
        print(username)
        passdict[organisation][username] = password
        self.set_passdict(passdict)

    # Check if given password has already been used for another account
    def existing_pass(self, addPass):
        passdict = self._passdict
        for organisation, orgdict in passdict.items():
            for username, password in orgdict.items():
                if addPass == password:
                    return True
        return False
    # Remove account
    def remove_passman_account(self):
        print('in remove function')
        os.remove('passfile.bin')
        os.remove('stored_cred.bin')
        self._username = None
        self._enc = None
        self._masterpassword = None
        self._passdict = None

    #===========================================================================
    # Helper methods
    # Validate password form...returns byte string
    def to_byte_string(self, masterpassword):
        try:
            password = masterpassword.encode('utf-8') # Convert to byte string
        except ValueError:
            with open('Error.txt', 'a+') as f:
                f.write('Password invalid value' + datetime.today())
                print('Password invalid value')
        return password
