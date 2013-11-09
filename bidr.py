# -*- coding: utf_8 -*-

'''
@created: Nov 08 2013
@author: Brendan Ashby & Zach Jablons
@summary: bidr is a bidding system utilizing social networks
@copyright: Copyright 2013 - All Rights Reserved
@license: GPLv3
'''

# Python - Stdlib Imports
import sys
import time
import os
import logging
import argparse

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

# Build the Flask App
from secrets import CONSUMER_ID, CONSUMER_SECRET, APP_SECRET
app = Flask(__name__)
app.secret_key = APP_SECRET
# App debugging | Comment out when deploying!!!
app.debug = True

# Load default config and override config from an environment variable
'''
app.config.update(dict(
    DATABASE='/db/bidr.db',
    DEBUG=True,
    SECRET_KEY='VPzMCCNUT5FWj6qD', # randomly generated
    USERNAME='bidr',
    PASSWORD='default'
))
'''

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

if __name__ == "__main__":
    app.run(host='0.0.0.0')