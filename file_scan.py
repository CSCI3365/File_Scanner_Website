#!/usr/bin/env python3

from flask import Flask, requests
import os

# Author:           Michael Roberts
# Date:             08/16/2024
# MVP Purpose:      to take a file and scan it through Virustotal and output some data
# Execution:        this should be handled in the browser 
# Dependencies:     you need to have the VirusTotal API installed as an Env Variable, in your .bashrc file on your computer to run this

# Variables
# There are three hash functions and the url of where we are building the website. The website location variable should be updated to include a certain file. 

md5 = os.system("md5sum #file")
sha256 = os.system("sha256sum #file")
sha1 = os.system("sha1sum #file")
website_location = 'https://github.com/CSCI3365/File_Scanner_Website'
apikey = os.getenv("VT_API2")

# I imported Flask as a starting point and to maybe develop from it since it interacts with http/https methods

app = Flask(__name__)

@app.route()

# Functions

'''
def scan_file(file):
    with open(#file, "r") as file:
'''
'''
def url():
'''

