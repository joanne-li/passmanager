'''
Flask server which handles all the communication between
front and backend

Acknowledgement: used semantic-ui for front-end build

Created 11/04/2020
@author: joanne-li
'''
import os
import flask
from flask import Flask, request, redirect, jsonify, render_template, url_for
from flask_login import LoginManager, current_user, login_required, login_user, logout_user
from Login import *
from Encrypt import *


# ========= Initialise app =====================================================
app = flask.Flask('__main__')

# Generate a key to encrypt cookies for client
app.secret_key = os.urandom(16)
loginManager = LoginManager()
loginManager.setup_app(app)

# Create Account object to perform operations on
encrypt = Encrypt()

# Create log of logged in users
loggedUsers = LoggedUsers()

# ==============================================================================
# Load the current user's details, whoever the user is in this current session
@loginManager.user_loader
def load_user(user_id):
    return loggedUsers.get_user(user_id)

@app.route('/login', methods=['GET','POST'])
def login():
    if current_user.is_anonymous:
        if request.method == 'POST':
            # Grab post request data
            username = request.form['username']
            password = request.form['password']
            if encrypt.verify_login(username, password):
                userObj = Login(username, password)
                userObj.account.set_masterpassword(password)
                login_user(userObj)
                userObj.authenticate = True
                loggedUsers.add_user(userObj)
                return redirect(url_for('landing'))
            else:
                return render_template('login.html', loginError=1)
        else:
            if not os.path.exists('stored_cred.bin'):
                return render_template('confirmation.html', message="Account does not exist for this device yet. Please create a new account.")
            return render_template('login.html')
    else:
        return redirect(url_for('landing'))

@app.route('/logout')
@login_required
def logout():
    loggedUsers.remove_user(current_user)
    logout_user()
    return redirect(url_for('landing'))

# ==============================================================================
# Landing page or root. Option to login or create account
@app.route('/', methods=['GET', 'POST'])
def landing():
    if current_user.is_anonymous:
        return render_template('landing.html')
    else:
        return render_template('home.html', user=current_user.account.username)


# Create an account
@app.route('/account', methods=['GET','POST'])
def pass_man_account():
    if request.method == 'GET':
        if os.path.exists('passfile.bin'):
            return render_template('confirmation.html', message="Account already exists on this device. Please sign into existing account")
        return render_template('account_creation.html')
    else:
        username = request.form['username']
        password = request.form['password']
        # TODO check for password entropy if time

        # Create account
        userObj = Login(username, password)
        userObj.account.create_account(password)
        login_user(userObj)
        userObj.authenticate = True
        loggedUsers.add_user(userObj)

        return redirect(url_for('landing'))

# Precursor to to editing credentials
@app.route('/viewpasswords', methods=['GET'])
@login_required
def view_passwords():
    passwords = current_user.account.get_passfile()
    return render_template('viewpasswords.html', passdict=passwords, length=len(passwords))

@app.route('/showpasswords', methods=['GET'])
@login_required
def show_passwords():
    passwords = current_user.account.get_passfile()
    return render_template('showpasswords.html', passdict=passwords, length=len(passwords))


@app.route('/editcredentials', methods=['POST'])
@login_required
def edit_cred():
    # Grab queries
    args = request.args
    organisation = args.get('organisation')
    username = args.get('username')
    password = args.get('password')

    if request.form['button input'] == 'change password':
        return render_template('editcred.html', setting='changePass', organisation=organisation, username=username, password=password)
    elif request.form['button input'] == 'change username':
        return render_template('editcred.html', setting='changeUsername', organisation=organisation, username=username, password=password)
    elif request.form['button input'] == 'delete account':
        # Delete account from password dictionary
        user = current_user.account
        user.remove_account(organisation, username)
        user._enc.encrypt_pass(user._enc.derive_filekey(user._masterpassword), user.get_passdict())

        # Display passwords page again
        passwords = user.get_passfile()
        return render_template('viewpasswords.html', passdict=passwords, length=len(passwords))

@app.route('/addaccount', methods=['GET','POST'])
@login_required
def add_account():
    if request.method == 'GET':
        print('here')
        return render_template('addaccount.html')
    else:
        organisation = request.form['organisation']
        username = request.form['username']
        password = request.form['password']
        user = current_user.account
        if user.existing_pass(password):
            return render_template('addaccount.html', existingpass=1)

        user.add_account(organisation, username, password)
        user._enc.encrypt_pass(user._enc.derive_filekey(user._masterpassword), user.get_passdict())
        # Display passwords page again
        passwords = user.get_passfile()
        print(passwords)
        return render_template('viewpasswords.html', passdict=passwords, length=len(passwords))

@app.route('/confirmchange', methods=['POST'])
@login_required
def confirm_change():
    accountname = request.args.get('username')
    organisation = request.args.get('organisation')
    try:
        result = request.form['confirm new password']
        # Change password of current users account
        user = current_user.account
        print('here 1')
        if user.existing_pass(result):
            print('here 2')
            return render_template('editcred.html', setting="changePass", existingpass=1)

        # Change the password to process memory (python dictionary)
        user.edit_acc_password(organisation, accountname, result)
        # Change to local file
        user._enc.encrypt_pass(user._enc.derive_filekey(user._masterpassword), user.get_passdict())
        message = "Changed password for " + accountname + " from " + organisation + " account."
        return render_template('confirmation.html', message=message)
    except:
        result = request.form['confirm new username']
        user = current_user.account
        user.edit_acc_username(organisation, accountname, result)
        # Change to local file
        user._enc.encrypt_pass(user._enc.derive_filekey(user._masterpassword), user.get_passdict())
        message = "Changed username from " + accountname + " to " + result + " for " + organisation + " account."
        return render_template('confirmation.html', message=message)

    return redirect(url_for('landing'))

# Manage account account settings
@app.route('/accountsettings', methods=['GET', 'POST'])
@login_required
def account_settings():
    if request.method == 'GET':
        return render_template('accountsettings.html')
    else:
        # If changing password
        # Grab post request data
        curpassword = request.form['current password']
        if encrypt.verify_login(current_user.account._username, curpassword):
            newPassword = request.form['new password']
            current_user.account.change_master_pass(newPassword)
            return render_template('confirmation.html', message="Master password successfully changed")
        else:
            return render_template('accountsettings.html', loginError=1)

@app.route('/deletion', methods=['POST'])
@login_required
def delete_account():
    # Todo verify login for removal
    current_user.account.remove_passman_account()
    # Logout current user
    logout_user()
    return render_template('confirmation.html', message="Account has been deleted")

# ====================================
# TODO
# redirect to landing page instead if anonymous
# if not anonymous, redirect to home page
@app.errorhandler(404)
def page_not_found(e):
    # note that we set the 404 status explicitly
    return render_template('404.html'), 404

@app.login_manager.unauthorized_handler
def unauth_handler():
    return redirect(url_for('landing'))


app.run(debug=True)
