'''
Testing the file woohoo

Created 4/4/2020
@author: joanne-li
'''
from Account import *
from Encrypt import *

acc = Account('joanne')
acc.create_account('password')
print(acc.verify_login(b'password'))
print(acc.verify_login(b'passWord'))
print(acc.verify_login(b'passW0rd'))
print(acc.verify_login(b'passw ord'))
print(acc.verify_login(b'passw 0rd'))
