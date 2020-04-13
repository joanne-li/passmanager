'''
Login wrapper function
Created 12/04/2020
@author: joanne-li
'''
from flask_login import UserMixin, AnonymousUserMixin
from Account import *

class LoggedUsers():
    def __init__(self):
        self._loggedUsers = []

    def add_user(self, user):
        self._loggedUsers.append(user)

    def remove_user(self, user):
        self._loggedUsers.remove(user)

    def get_user(self, username):
        for i in self._loggedUsers:
            if i.account.username == username:
                return i
        return AnonymousUserMixin()



class Login(UserMixin):
    def __init__(self, username, password):
        self._acc = Account(username, password)

    @property
    def account(self):
        return self._acc

    @account.setter
    def account(self, acc):
        self._acc = acc

    def get_id(self):
        return self._acc.username
