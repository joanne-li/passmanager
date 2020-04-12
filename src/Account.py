'''
Add, edit, modify user information and details

Created 4/4/2020
@author: joanne-li
'''
import json
from Encrypt import Encrypt
from Crypto.Random import get_random_bytes

class Account():
    def __init__(self, username):
        self._username = username
        self._enc = Encrypt()
        self._passfile = self.create_pass_file()

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
        passfile = json.dumps(self._passfile)
        passfile = self.to_byte_string(passfile)
        self._enc.encrypt_pass(fileKey, passfile)

        fileKey = None # Make sure to delete this unencrypted key!

    def create_pass_file(self):
        return dict()

    # Get unencrypted password file dictionary
    def get_passfile(self):
        return self._enc.decrypt_passfile(self._masterpassword)

    def set_passfile(self, passfiledict):
        self._passfile = passfiledict

    def set_masterpassword(self, password):
        self._masterpassword = self.to_byte_string(password)

    def change_master_pass(self, oldMaster, newMaster):
        oldMaster = self.to_byte_string(oldMaster)
        newMaster = self.to_byte_string(newMaster)
        # Decrypt passwordFileKey
        dkey, authkey = self._enc.derive_key_pass(oldMaster, self._enc.get_salt())
        passwordFileKey = self._enc.decrypt_ciphertext(dkey, self._enc.get_obsc_key(), self._enc.get_IV(), self._enc.get_tag())

        # Encypt passwordFileKey with newMaster
        self._enc.encrypt_user_info(self._username, newMaster, passwordFileKey)
        self._masterpassword = newMaster
        passwordFileKey = None

    # ==========================================================================
    # Manage passwords in the password manager
    # Add account to passfile (dictionary type)
    # username = account username, not the password manager username
    # passdict = {organisation: {username1: pass1, username2: pass2}, organisation2....}
    def add_account(self, organisation, username, password):
        passdict = self._passfile
        if passdict.get(organisation) is None:
            passdict[organisation] = {}
        passdict[organisation][username] = password
        return passdict

    # Remove account frrom passfile
    def remove_account(self, organisation, username):
        passdict = self._passfile
        del passdict[organisation][username]
        if len(passdict[organisation]) == 0: del passdict[organisation]
        return passdict

    # Edit account username
    def edit_acc_username(self, organisation, oldUsername, newUsername):
        passdict = self._passfile
        password = passdict[organisation][oldUsername]
        del passdict[organisation][oldUsername]
        passdict[organisation][newUsername] = password
        return passdict

    # Edit account password
    def edit_acc_password(self, organisation, username, password):
        passdict = self._passfile
        passdict[organisation][username] = password
        return passdict

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
