# -*- coding: utf_8 -*-

'''
@created: Nov 08 2013
@author: Brendan Ashby & Zach Jablons
@summary: bidr is a bidding system utilizing social networks
@copyright: Copyright 2013 - All Rights Reserved
@license: GPLv3? No Idea
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
	from flask import Flask
	app = Flask(__name__)
except ImportError:
	log.error("Failed to import Flask Library. Install it: http://flask.pocoo.org/")
	sys.exit()

@app.route("/")
def hello():
    return "Hello YHACK!"

if __name__ == "__main__":
    app.run()