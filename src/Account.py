'''

Created 4/4/2020
@author: joanne-li
'''
from Encrypt import Encrypt as enc
from Crypto.Random import get_random_bytes

class Account():
    def __init__(self, username):
        self._username = username

    # Create a new user account
    def create_account(self, masterpassword):
        try:
            password = masterpassword.encode('utf-8') # Convert to byte string
        except ValueError:
            with open('Error.txt', 'a+') as f:
                f.write('Password invalid value' + datetime.today())
                print('Password invalid value')
        # Unencrypted state; key to encrypt passfile
        fileKey = get_random_bytes(self._passFileKeylen)
        enc.encrypt_user_info(self._username, password, fileKey)
        del fileKey # Make sure to delete this unencrypted key!


    def change_master_pass(self, oldMaster, newMaster):
        # Decrypt passwordFileKey
        dkey, authkey = derive_key_pass(oldMaster, get_salt())
        passwordFileKey = decrypt_ciphertext(dkey, get_obsc_key(), get_IV(), get_tag())

        # Encypt passwordFileKey with newMaster
        enc.encrypt_user_info(self._username, newMaster, passwordFileKey)
        del passwordFileKey

    # Verify login attempt or verify password to change master password
    def verify_login(self, password):
        derivedKey, authKey = enc.derive_key_pass(password, get_salt())
        return authKey == enc.get_authKey()

    # Add account to passfile (dictionary type)
    # username = account username, not the password manager username
    # passfile = {organisation: {username1: pass1, username2: pass2}, organisation2....}
    def add_account(self, passfile, organisation, username, password):
        passfile[organisation][username] = password
        return passfile

    # Remove account frrom passfile
    def remove_account(self, passfile, organisation, username):
        del passfile[organisation][username]
        if len(passfile[organisation]) == 0: del passfile[organisation]
        return passfile

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
