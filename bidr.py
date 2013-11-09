# -*- coding: utf_8 -*-

'''
@created: Nov 08 2013
@author: Brendan Ashby & Zach Jablons
@summary: bidr is a bidding system utilizing social networks
@license: GPLv3
'''

# Python - Stdlib Imports
import sys
import time
import os
import logging
import argparse
import datetime
from sqlite3 import dbapi2 as sqlite3

# Import - Bidr libraries/vars
from bidrlib import database
from bidrlib.secrets import CONSUMER_ID, CONSUMER_SECRET, APP_SECRET, SECRET_KEY, USERNAME_DB, PASSWORD_DB, HOST_DB, PORT_DB

# Initiate Logging Globals
logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger('BIDRLOG')

# Imports - Dependancies
try:
	from flask import Flask, request, redirect, session, render_template, flash
	from werkzeug.security import generate_password_hash, check_password_hash
except ImportError:
	log.error("Failed to import Flask Library. Install it: http://flask.pocoo.org/")
	sys.exit()
try:
	import requests
except ImportError:
	log.error("Failed to import Python Requests Library. Install it: http://www.python-requests.org/en/latest/")
	sys.exit()
try:
	from wtforms import Form, BooleanField, StringField, validators, PasswordField, SubmitField, TextAreaField, DecimalField, RadioField
	from wtforms.ext.dateutil.fields import DateTimeField
except ImportError:
	log.error("Failed to import Python WTForms Library. Install it: https://pypi.python.org/pypi/WTForms")
	log.error("If you are still seeing errors you may still need to install python-dateutils. Install it: http://labix.org/python-dateutil")
	sys.exit()
try:
	from flask.ext.mongoengine import MongoEngine, MongoEngineSessionInterface
except ImportError:
	log.error("Failed to import Flask-MongoEngine Library. Install it: https://github.com/MongoEngine/flask-mongoengine")
	sys.exit()

# Build the Flask App
app = Flask(__name__, template_folder="assets/templates", static_folder="assets/static")
app.secret_key = APP_SECRET
# App debugging | Comment out when deploying!!!
app.debug = True
# Set flask/mongodb configuration arguments
app.config["MONGODB_SETTINGS"] = {"DB": "bidr", "USERNAME": USERNAME_DB, "PASSWORD": PASSWORD_DB, "HOST": HOST_DB, "PORT": PORT_DB}
app.config.update(dict(
	DEBUG=True,
	SECRET_KEY=SECRET_KEY,
))

# Initialize our MongoDB
db = MongoEngine(app)
# Give Session control to mongoengine
app.session_interface = MongoEngineSessionInterface(db)

# Define MongoDB Schema
class Group(db.Document):
	name = db.StringField(max_length=255, required=True)
	users = db.ListField(db.ReferenceField('User'))

class Account(db.Document):
	domain = db.StringField(max_length=255, required=True)
	arguments = db.StringField(required=True)

class User(db.Document):
	username = db.StringField(min_length=4, max_length=25, required=True)
	emailaddress = db.EmailField(min_length=6, max_length=35, required=True)
	password_hash = db.StringField(min_length=8, max_length=66, required=True)
	friends = db.ListField(db.ReferenceField('User'))
	friend_requests_pending = db.ListField(db.ReferenceField('User'))
	friend_requests_sent = db.ListField(db.ReferenceField('User'))
	accounts = db.ListField(db.ReferenceField(Account))
	groups = db.ListField(db.ReferenceField(Group))
	auctions_available = db.ListField(db.ReferenceField('Auction'))
	auctions_in = db.ListField(db.ReferenceField('Auction'))
	auctions_pending = db.ListField(db.ReferenceField('Auction'))
	auctions_past = db.ListField(db.ReferenceField('Auction'))

class Bid(db.Document):
	bidder = db.ReferenceField(User, required=True)
	auction = db.ReferenceField('Auction', required=True)
	amount = db.DecimalField(precision=2, required=True)
	time = db.DateTimeField(default=datetime.datetime.now, required=True)

class Auction(db.Document):
	created_at = db.DateTimeField(default=datetime.datetime.now, required=True)
	creator = db.ReferenceField(User, required=True)
	min_price = db.DecimalField(precision=2, default=0.00)
	title = db.StringField(min_length=5, max_length=100, required=True)
	description = db.StringField(required=True)
	tags = db.ListField(db.StringField(max_length=100, required=True))
	comments = db.ListField(db.StringField(max_length=255))
	expiration = db.DateTimeField(required=True)
	isPublic = db.BooleanField(default=False)
	isRunning = db.BooleanField(default=True)

	def __unicode__(self):
		return self.title

	meta = {
		'ordering': ['-created_at']
	}

# Define WTForms Schema
class RegistrationForm(Form):
	username = StringField('Username', [validators.InputRequired(message=(u'You must supply a username.')), validators.Length(min=4, max=25, message=(u'A username must be atleast 4 and no more than 25 characters.'))])
	email = StringField('Email Address', [validators.InputRequired(message=(u'You must supply an email address.')), validators.Length(min=6, max=35, message=(u'An email address must be atleast 6 and no more than 35 characters.')), validators.Email(message=(u'Invalid email address format.')), validators.EqualTo('confirmEmail', message=(u'Email addresses must match.'))])
	confirmEmail = StringField('Repeat Email Address', [validators.InputRequired(message=(u'You must retype your email address.')), validators.Length(min=6, max=35, message=(u'An email address must be atleast 6 and no more than 35 characters.')), validators.Email(message=(u'Invalid email address format.'))])
	password = PasswordField('Password', [validators.InputRequired(message=(u'You must supply a password.')), validators.Length(min=8, max=32, message=(u'A password must be atleast 8 and no more than 32 characters.')), validators.EqualTo('confirmPassword', message='Passwords must match.')])
	confirmPassword = PasswordField('Repeat Password', [validators.InputRequired(message=(u'You must retype your password.')), validators.Length(min=8, max=32, message=(u'A password must be atleast 8 and no more than 32 characters.'))])
	accept_rules = BooleanField('I accept that Brendan has a huge dick.', [validators.InputRequired(message=(u'You must agree to the terms.'))])
	submit = SubmitField('Register')

class LoginForm(Form):
	username = StringField('Username', [validators.InputRequired(message=(u'You must supply a username.')), validators.Length(min=4, max=25, message=(u'A username must be atleast 4 and no more than 25 characters.'))])
	password = PasswordField('Password', [validators.InputRequired(message=(u'You must supply a password.')), validators.Length(min=8, max=32, message=(u'A password must be atleast 8 and no more than 32 characters.'))])
	submit = SubmitField('Login')

class AuctionForm(Form):
	title = StringField('Title', [validators.InputRequired(message=(u'You must supply an auction title.')), validators.Length(min=5, max=100, message=(u'A title must be atleast 5 and no more than 100 characters.'))])
	description = TextAreaField('Description', [validators.InputRequired(message=(u'You must supply an auction description.')), validators.Length(min=15, message=(u'A title must be atleast 15 characters.'))])
	#tags = db.ListField(db.StringField(max_length=100, required=True))
	expiration = DateTimeField("Expiration", [validators.InputRequired(message=(u'You must supply an auction expiration time.'))])
	min_price = DecimalField("Minimum Price", places=2)
	isPublic = BooleanField("List publicly")
	submit = SubmitField('Create')

class editUserPasswordForm(Form):
	currentPassword = PasswordField('Current Password', [validators.InputRequired(message=(u'You must supply your current password.')), validators.Length(min=8, max=32, message=(u'Your current password will be atleast 8 and no more than 32 characters.'))])
	newPassword = PasswordField('New Password', [validators.InputRequired(message=(u'You must supply a new password.')), validators.Length(min=8, max=32, message=(u'Your new password must be atleast 8 and no more than 32 characters.')), validators.EqualTo('confirmNewPassword', message='New passwords must match.')])
	confirmNewPassword = PasswordField('Retpye New Password', [validators.InputRequired(message=(u'You must retpye your new password.')), validators.Length(min=8, max=32, message=(u'Your retyped new password must be atleast 8 and no more than 32 characters.'))])
	submit = SubmitField('Change Password')

class searchUserForm(Form):
	searchVector = RadioField('Match Against', choices=['User Email Address', 'Username'])
	emailaddress = StringField('Email Address', [validators.Length(min=6, max=35, message=(u'An email address to be searched for must be atleast 6 and no more than 35 characters.')), validators.Email(message=(u'Invalid target email address format.'))])
	username = StringField('Username', [validators.Length(min=4, max=25, message=(u'A username to be searched for must be atleast 4 and no more than 25 characters.'))])

class sendFriendRequestForm(Form):
	username = StringField('Username', [validators.Length(min=4, max=25, message=(u'A username to be friended must be atleast 4 and no more than 25 characters.'))])
	emailaddress = StringField('Email Address', [validators.Length(min=6, max=35, message=(u'An email address to be friended must be atleast 6 and no more than 35 characters.')), validators.Email(message=(u'Invalid email address format.'))])
	submit = SubmitField('Send Request')

class acceptFriendRequestForm(Form):
	username = StringField('Username', [validators.Length(min=4, max=25, message=(u'A username to be friended must be atleast 4 and no more than 25 characters.'))])
	emailaddress = StringField('Email Address', [validators.Length(min=6, max=35, message=(u'An email address to be friended must be atleast 6 and no more than 35 characters.')), validators.Email(message=(u'Invalid email address format.'))])	
	submit = SubmitField('Accept Request')

class createGroupForm(Form):
	name = StringField('Group Name', [validators.InputRequired(message=(u'You must supply your group with a name.')), validators.Length(min=5, max=255, message=(u'Your group name should be atleast 5 and no more than 255 characters.'))])
	#users = ListField(db.ReferenceField('User'))
	submit = SubmitField('Create Group')

class addToGroupForm(Form):
	username = StringField('Username', [validators.InputRequired(message=(u'You must supply a username to add to a group.'))])
	submit = SubmitField('Add user to group')

@app.route('/')
def index():
	
	return render_template('index.html')

	'''
	if session.get('venmo_token'):
		return 'Your Venmo token is %s' % session.get('venmo_token')
	else:
		return redirect('https://api.venmo.com/oauth/authorize?client_id=%s&scope=make_payments,access_profile&response_type=code' % CONSUMER_ID)
	'''

@app.route('/register', methods=['GET', 'POST'])
def registerUser():
	if request.method == 'POST':
		form = RegistrationForm(request.form)
		if form.validate():
			if len(User.objects(username=request.form['username'])) == 0:
				user = User(username=request.form['username'], emailaddress=request.form['email'], password_hash=generate_password_hash(request.form['password'])).save()
				session['authenticated'] = True
				session['username'] = user.username
				return redirect('/dashboard') 
			else:
				flash("Username is already taken.", category="warning")
				return render_template('register.html', form=form)
		else:
			return render_template('register.html', form=form)
	elif request.method == 'GET':
		form = RegistrationForm()
		return render_template('register.html', form=form)
	else:
		flash("Invalid HTTP Request.", category="warning")
		return redirect('/')

@app.route('/login', methods=['GET', 'POST'])
def loginUser():
	if request.method == 'POST':
		form = LoginForm(request.form)
		if form.validate():
			matches = User.objects(username=request.form['username'])
			if len(matches) == 1 and check_password_hash(matches.first().password_hash, request.form['password']):
				session['authenticated'] = True
				session['username'] = request.form['username']
				return redirect('/dashboard') 
			else:
				flash("Invalid credentials.", category="warning")
				return render_template('login.html', form=form)
		else:
			return render_template('login.html', form=form)
	elif request.method == 'GET':
		form = LoginForm()
		return render_template('login.html', form=form)
	else:
		flash("Invalid HTTP Request.", category="warning")
		return redirect('/')


@app.route('/logout', methods=['GET'])
def logoutUser():
	if request.method == 'GET':
		if 'authenticated' in session and session['authenticated'] and 'username' in session:
			flash("You have been logged out of the account: %s" % session['username'])
			del session['authenticated']
			del session['username']
			return redirect('/login')
		else:
			flash("You are currently not logged into an account.")
			return redirect('/login')
	else:
		flash("Invalid HTTP Request.", category="warning")
		return redirect('/')

@app.route('/auth')
def oauth_authorized():
	AUTHORIZATION_CODE = request.args.get('code')
	data = {
		"client_id":CONSUMER_ID,
		"client_secret":CONSUMER_SECRET,
		"code":AUTHORIZATION_CODE
		}
	url = "https://api.venmo.com/oauth/access_token"
	response = requests.post(url, data)
	response_dict = response.json()
	access_token = response_dict.get('access_token')
	user = response_dict.get('user')

	session['venmo_token'] = access_token
	session['venmo_username'] = user['username']

	if session.get('venmo_token'):
		return 'Success! Token is %s' % session.get('venmo_token')
	else:
		return "Failed to get a token bro. Fix dat shit now."

@app.route('/dashboard')
def dashboard():
	''' list active auctions '''
	if 'authenticated' in session:
		return render_template('dashboard.html')
	else:
		flash("You must authenticate first.", category="warning")
		return redirect("/login")

@app.route('/auction/create', methods=['GET', 'POST'])
def createAuction():
	if 'authenticated' in session:
		if request.method == 'POST':
			form = AuctionForm(request.form)
			if form.validate():
				creator = User.objects(username=session['username']).first()
				isPublic = False # TODO: the default bool is being weird, so using a simple workaround for now.
				if 'isPublic' in request.form:
					isPublic = request.form['isPublic']
				auction = Auction(creator=creator, min_price=request.form['min_price'], title=request.form['title'], description=request.form['description'], tags=["Foo, Bar"], expiration=request.form['expiration'], isPublic=isPublic).save()
				flash("Successfully created auction.")
				return redirect('auction/%s' % str(auction.id))
			else:
				return render_template('createAuction.html', form=form)
		elif request.method == 'GET':
			form = AuctionForm()
			return render_template('createAuction.html', form=form)
		else:
			flash("Invalid HTTP Request.", category="warning")
			return redirect('/')
	else:
		flash("You must authenticate first.", category="warning")
		return redirect("/login")

@app.route('/auction/<string:auction_id>')
def auctionListing(auction_id):
	''' list active auctions '''

	if 'authenticated' in session:
		user = User.objects(username=session['username']).first()
		match = Auction.objects(id=auction_id).first()
		valid = False
		for _list in [user.auctions_available, user.auctions_in, user.auctions_pending, user.auctions_past]:
			if match in _list:
				valid = True
				break
		if valid:
			return "You may view this auction."
		else:
			return "You are not allowed to view this auction."
	else:
		flash("You must authenticate first.", category="warning")
		return redirect("/login")

@app.route('/user/<string:username>/settings', methods=['GET'])
def userSettings(username):
	''' list settings for user ( must be logged in ) '''
	if 'authenticated' in session and username == session['username']:
		matches = User.objects(username=username)
		if len(matches):
			if request.method == "GET":
				return render_template('editUser.html', user=matches.first())
			else:
				flash("Invalid HTTP Request.", category="warning")
				return redirect('/')
		else:
			abort(404)
	else:
		flash("You must authenticate first.", category="warning")
		return redirect("/login")

@app.route('/user/<string:username>/settings/changepassword', methods=['GET', 'POST'])
def changeUserPassword(username):
	if 'authenticated' in session and username == session['username']:
		matches = User.objects(username=username)
		if len(matches):
			if request.method == 'POST':
				editPasswordForm = editUserPasswordForm(request.form)
				if editPasswordForm.validate():
					if check_password_hash(matches.first().password_hash, request.form['currentPassword']):
						# Do user edits TODO: actually edit the values and allow for more forms and stuff here
						return "Good Job."
					else:
						flash("Invalid value for the current user password.", category="warning")
						return render_template('editUser_password.html', form=editPasswordForm, user=matches.first())
				else:
					return render_template('editUser_password.html', form=editPasswordForm, user=matches.first())
			elif request.method == "GET":
				form = editUserPasswordForm()
				return render_template('editUser_password.html', form=form, user=matches.first())
			else:
				flash("Invalid HTTP Request.", category="warning")
				return redirect('/')
		else:
			abort(404)
	else:
		flash("You must authenticate first.", category="warning")
		return redirect("/login")

@app.route('/user/<string:username>/settings/sendfriendrequest', methods=['GET', 'POST'])
def sendFriendRequest(username):
	if 'authenticated' in session and username == session['username']:
		matches = User.objects(username=username)
		if len(matches):
			if request.method == 'POST':
				aSendFriendRequestForm = sendFriendRequestForm(request.form)
				if aSendFriendRequestForm.validate():
					target = User.objects(username=request.form['username'])
					target.update_one(add_to_set__friend_requests_pending=matches.first())
					matches.update_one(add_to_set__friend_requests_sent=target.first())
					flash("Request Sent to %s" % target.first().username)
					form = sendFriendRequestForm()
					return render_template('editUser_sendfriendrequest.html', form=form, user=matches.first())
				else:
					return render_template('editUser_sendfriendrequest.html', form=aSendFriendRequestForm, user=matches.first())
			elif request.method == "GET":
				form = sendFriendRequestForm()
				return render_template('editUser_sendfriendrequest.html', form=form, user=matches.first())
			else:
				flash("Invalid HTTP Request.", category="warning")
				return redirect('/')
		else:
			abort(404)
	else:
		flash("You must authenticate first.", category="warning")
		return redirect("/login")

@app.route('/user/<string:username>/settings/acceptfriendrequest', methods=['GET', 'POST'])
def acceptFriendRequest(username):
	if 'authenticated' in session and username == session['username']:
		matches = User.objects(username=username)
		if len(matches):
			if request.method == 'POST':
				aAcceptFriendRequestForm = acceptFriendRequestForm(request.form)
				if aAcceptFriendRequestForm.validate():
					# Do user edits TODO: actually edit the values and allow for more forms and stuff here
					target = User.objects(username=request.form['username'])
					target.update_one(pull__friend_requests_sent=matches.first())
					matches.update_one(pull__friend_requests_pending=target.first())
					# Add each other to friends
					target.update_one(add_to_set__friends=matches.first())
					matches.update_one(add_to_set__friends=target.first())
					flash("Good Job accepting a friend request.")
					form = acceptFriendRequestForm()
					return render_template('editUser_acceptfriendrequest.html', form=form, user=matches.first())
				else:
					return render_template('editUser_acceptfriendrequest.html', form=aAcceptFriendRequestForm, user=matches.first())
			elif request.method == "GET":
				form = acceptFriendRequestForm()
				return render_template('editUser_acceptfriendrequest.html', form=form, user=matches.first())
			else:
				flash("Invalid HTTP Request.", category="warning")
				return redirect('/')
		else:
			abort(404)
	else:
		flash("You must authenticate first.", category="warning")
		return redirect("/login")

@app.route('/user/<string:username>/settings/creategroup', methods=['GET', 'POST'])
def createGroup(username):
	if 'authenticated' in session and username == session['username']:
		matches = User.objects(username=username)
		if len(matches):
			if request.method == 'POST':
				aGroupForm = createGroupForm(request.form)
				if aGroupForm.validate():
					group = Group(name=request.form['name']).save()
					User.objects(username=username).update_one(add_to_set__groups=group)
					# Do user edits TODO: actually edit the values and allow for more forms and stuff here
					#target = User.objects(username=request.form['username'])
					#target.update_one(pull__friend_requests_sent=matches.first())
					#matches.update_one(pull__friend_requests_pending=target.first())
					# Add each other to friends
					#target.update_one(add_to_set__friends=matches.first())
					#matches.update_one(add_to_set__friends=target.first())
					flash("Good Job creating a new group.")
					form = createGroupForm()
					return render_template('createGroup.html', form=form, user=matches.first())
				else:
					return render_template('createGroup.html', form=aGroupForm, user=matches.first())
			elif request.method == "GET":
				form = createGroupForm()
				return render_template('createGroup.html', form=form, user=matches.first())
			else:
				flash("Invalid HTTP Request.", category="warning")
				return redirect('/')
		else:
			abort(404)
	else:
		flash("You must authenticate first.", category="warning")
		return redirect("/login")

@app.route('/group/<string:group_id>', methods=['GET', 'POST'])
def viewGroup(group_id):
	if 'authenticated' in session:
		user = User.objects(username=session['username']).first()
		group = Group.objects(id=group_id).first()
		if group in user.groups:
			if request.method == 'POST':
				anAddToGroupForm = addToGroupForm(request.form)
				if anAddToGroupForm.validate():
					user = User.objects(username=request.form['username'])
					Group.objects(id=group_id).update_one(add_to_set__users=user)
					flash("Good Job adding a user to a group.")
					form = addToGroupForm()
					return render_template('addToGroup.html', form=form, user=user, group=group)
				else:
					return render_template('addToGroup.html', form=anAddToGroupForm, user=user, group=group)
			elif request.method == "GET":
				form = addToGroupForm()
				return render_template('addToGroup.html', form=form, user=user, group=group)
			else:
				flash("Invalid HTTP Request.", category="warning")
				return redirect('/')
		else:
			flash("You don't have a group by this name", category='warning')
			redirect('/')
	else:
		flash("You must authenticate first.", category="warning")
		return redirect("/login")

@app.route('/user/<string:username>')
def userProfile(username):
	''' list active auctions '''
	user = User.objects(username=username)
	if not len(user):
		abort(404)
	else:
		return render_template('userProfile.html', user=user.first())

@app.errorhandler(404)
def page_not_found(error):
    #return render_template('page_not_found.html'), 404
    return "Oops, 404!", 404

if __name__ == "__main__":
	app.run(host='0.0.0.0', port=80)