#!/usr/bin/env python3

#from flask import Flask, requests
import requests 
import os

# Author:           Michael Roberts
# Date:             08/16/2024
# MVP Purpose:      to take a file and scan it through Virustotal and output some data
# Execution:        this should be handled in the browser 
# Dependencies:     you need to have the VirusTotal API installed as an Env Variable, or in your .bashrc file on your computer to run this

# Variables
# There are three hash functions and the url of where we are building the website. The website location variable should be updated to include a certain file. 
# the vt url for uploading a file is included as well as where the script can find each persons specific api key. 
md5 = os.system("md5sum #file")
sha256 = os.system("sha256sum #file")
sha1 = os.system("sha1sum #file")
website_location = 'https://github.com/CSCI3365/File_Scanner_Website'
vt_url = "https://www.virustotal.com/api/v3/files"
apikey = os.getenv("VT_API2")

'''
# I am commenting Flask out for the mvp right now. I dont think it is necessary but we may be able to implement it once the mvp is done.
# I imported Flask as a starting point and to maybe develop from it since it interacts with http/https methods
app = Flask(__name__)

@app.route()
'''
# Headers for VT to accept. These are required for Virustotal to be able to read and interpret the request
headers = {
    "accept": "application/json",
    "x-apikey": apikey,
    "content-type": "multipart/form-data"
}

# response is using the requests library to send a POST request to virusTotal with the specified parameters.
response = requests.post(vt_url, headers=headers)

# This should print out the information from VT in a readable format.
print(response.text)

'''
# Functions


def scan_file(file):
    with open(#file, "r") as file:


def url():
'''

