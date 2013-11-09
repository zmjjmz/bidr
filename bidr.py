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
	from wtforms import Form, BooleanField, StringField, validators, PasswordField, SubmitField, TextAreaField, DecimalField
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
	password_hash = db.StringField(min_length=8, max_length=64, required=True)
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
	return "This is a listing of an auction with ID %s" % auction_id

@app.route('/user/<string:username>/settings')
def userSettings(username):
	''' list settings for user ( must be logged in ) '''
	if 'authenticated' in session and username == session['username']:
		if len(User.objects(username=username)):
			return "Can Edit %s" % username
		else:
			return "Auth'd but user DNE. Which cannot happen but hey let's catch this corner case anyway."
	else:
		return "You are not authenticated to do that. Try <a href=\"/login\">logging</a> in first."

@app.route('/user/<string:username>')
def userProfile(username):
	''' list active auctions '''
	user = User.objects(username=username)
	if not len(user):
		return "No user found with this username."
	else:
		return render_template('userProfile.html', user=user.first())
		#return "This is a public profile relevent to username: %s | email: %s | password_hash: %s" % (user.username, user.emailaddress, user.password_hash)

@app.errorhandler(404)
def page_not_found(error):
    #return render_template('page_not_found.html'), 404
    return "Oops, 404!", 404

if __name__ == "__main__":
	app.run(host='0.0.0.0', port=80)