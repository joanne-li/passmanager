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


    # Create a new user account
    def create_account(self, masterpassword):
        try:
            password = masterpassword.encode('utf-8') # Convert to byte string
        except ValueError:
            with open('Error.txt', 'a+') as f:
                f.write('Password invalid value' + datetime.today())
                print('Password invalid value')

        # Unencrypted state; key to encrypt passfile
        fileKey = get_random_bytes(16)
        self._enc.encrypt_user_info(self._username, password, fileKey)

        # Create passfile
        passfile = self.create_pass_file()
        self._enc.encrypt_pass(fileKey, passfile)

        passfile = None # Make sure to delete this unencrypted key!
        fileKey = None # Make sure to delete this unencrypted key!

    def create_pass_file(self):
        return json.dumps(dict())


    def change_master_pass(self, oldMaster, newMaster):
        # Decrypt passwordFileKey
        dkey, authkey = self._enc.derive_key_pass(oldMaster, self._enc.get_salt())
        passwordFileKey = self._enc.decrypt_ciphertext(dkey, self._enc.get_obsc_key(), self._enc.get_IV(), self._enc.get_tag())

        # Encypt passwordFileKey with newMaster
        newMaster = newMaster.encode('utf-8')
        self._enc.encrypt_user_info(self._username, newMaster, passwordFileKey)
        passwordFileKey = None

    # Verify login attempt or verify password to change master password
    def verify_login(self, password):
        derivedKey, authKey = self._enc.derive_key_pass(password, self._enc.get_salt())
        return authKey == self._enc.get_authKey()


    # Add account to passfile (dictionary type)
    # username = account username, not the password manager username
    # passdict = {organisation: {username1: pass1, username2: pass2}, organisation2....}
    def add_account(self, organisation, masterpassword, username, password):
        passdict = decrypt_passfile(masterpassword)
        passdict[organisation][username] = password
        return passdict

    # Remove account frrom passfile
    def remove_account(self, organisation, username):
        passdict = decrypt_passfile(masterpassword)
        del passdict[organisation][username]
        if len(passdict[organisation]) == 0: del passdict[organisation]
        return passdict

    # Edit account username
    def edit_acc_username(self, passfile, organisation, oldUsername, newUsername):
        password = passfile[organisation][oldUsername]
        del passfile[organisation][oldUsername]
        passfile[organisation][newUsername] = password
        return passfile

    # Edit account password
    def edit_acc_password(self, passfile, organisation, username, password):
        passfile[organisation][username] = password
        return passfile
