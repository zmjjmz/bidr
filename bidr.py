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
from sqlite3 import dbapi2 as sqlite3

# Import - Bidr libraries/vars
from bidrlib import database
from bidrlib.secrets import CONSUMER_ID, CONSUMER_SECRET, APP_SECRET, SECRET_KEY_DB, USERNAME_DB, PASSWORD_DB

# Initiate Logging Globals
logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger('BIDRLOG')

# Imports - Dependancies
try:
	from flask import Flask, request, redirect, session
except ImportError:
	log.error("Failed to import Flask Library. Install it: http://flask.pocoo.org/")
	sys.exit()
try:
	import requests
except ImportError:
	log.error("Failed to import Python Requests Library. Install it: http://www.python-requests.org/en/latest/")
	sys.exit()

#######################
# Build the Flask App #
#######################
app = Flask(__name__)
app.secret_key = APP_SECRET
# App debugging | Comment out when deploying!!!
app.debug = True
# Load default config and override config from an environment variable
app.config.update(dict(
	DATABASE='/db/bidr.db',
	DEBUG=True,
	SECRET_KEY=SECRET_KEY_DB, # randomly generated
	USERNAME=USERNAME_DB,
	PASSWORD=PASSWORD_DB # randomly generated
))

@app.route('/')
def index():
	if session.get('venmo_token'):
		return 'Your Venmo token is %s' % session.get('venmo_token')
	else:
		return redirect('https://api.venmo.com/oauth/authorize?client_id=%s&scope=make_payments,access_profile&response_type=code' % CONSUMER_ID)

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
	return "This is a listing of all actions relevent to a user"

@app.route('/auction/<int:auction_id>')
def auctionListing(auction_id):
	''' list active auctions '''
	return "This is a listing of an auction with ID %d" % auction_id

@app.route('/user/<string:username>/settings')
def userSettings(username):
	''' list settings for user ( must be logged in ) '''
	return "This is the settings for user with username: %s" % username

@app.route('/user/<string:username>')
def userProfile(username):
	''' list active auctions '''
	return "This is a public profile relevent to username: %s" % username


if __name__ == "__main__":
	app.run(host='0.0.0.0', port=80)