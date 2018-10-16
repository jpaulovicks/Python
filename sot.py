#!/usr/bin/env python
# coding: utf-8
"""
    Project:        Security Operations Tool
    Description:    API Tool for various SOC tasks
    Version:        0.1
    Date:           2018
    Author:         Jason Paulovicks
    Notes:          1. Script Born
                    2. Currently only has VirusTotal API functions for Hash and URL reports

    License: MIT License

            Copyright (c)  2018    Jason Paulovicks

            Permission is hereby granted, free of charge, to any person obtaining a copy
            of this software and associated documentation files (the "Software"), to deal
            in the Software without restriction, including without limitation the rights
            to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
            copies of the Software, and to permit persons to whom the Software is
            furnished to do so, subject to the following conditions:

            The above copyright notice and this permission notice shall be included in all
            copies or substantial portions of the Software.

            THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
            IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
            FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
            AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
            LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
            OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
            SOFTWARE.
"""
from requests import get
from time import sleep
from os import system

# Global variables
# virustotal public api key (replace with your own public or private API key)
apikey = ''

# virustotal file hash report base url
filescanurl = 'https://www.virustotal.com/vtapi/v2/file/report'

# virustotal url report base url
urlscanreporturl = 'http://www.virustotal.com/vtapi/v2/url/report'


def get_hash_report(fhash):
    """
    Function will check a file hash against VirusTotal
    If hash is unknown (response code 0) message will be displayed
    If the hash is known then any positives will be outputted
    :param fhash:
    :return:
    """
    params = {'apikey': apikey, 'resource': fhash}
    response = get(filescanurl, params=params)
    json_response = response.json()
    if json_response['response_code'] == 1:
        if json_response['positives'] != 0:
            print(80 * "-")
            print("Submitted Hash: " + fhash)
            for key, value in json_response['scans'].items():
                if value['detected'] is True:
                    print(str(key) + "," + str(value['result']))
    else:
        print("Report doesnt exist")


def get_url_report(url, scan='1'):
    """
    Function will check a url against VirusTotal
    If url is unknown (response code 0) URL will be submitted automatically for scanning
    If the URL is known then any positive scanners will be outputted
    :param url:
    :param scan:
    :return:
    """
    params = {'apikey': apikey, 'resource': url, 'scan': scan}
    response = get(urlscanreporturl, params=params)
    json_response = response.json()
    if json_response['response_code'] == 1:
        if json_response['positives'] != 0:
            print(80 * "-")
            print("Submitted URL: " + url)
            for key, value in json_response['scans'].items():
                if value['detected'] is True:
                    print(str(key) + "," + str(value['result']))
    else:
        print("Report pending")


def ban(text, ch='-', length=80):
    """
    Simple banner file, displays basic information
    :param text:
    :param ch:
    :param length:
    :return:
    """
    spaced_text = '%s' % text
    banner = spaced_text.center(length, ch)
    print(banner)


def menu():
    """
    User menu displayed to user includes sub-menus
    :return:
    """
    system('clear')
    ban(text="Security Operations Tool")
    print("1. Check URLs")
    print("2. Check Hashes")
    print("3. Exit")
    ban(text="By: Jason Paulovicks")


if __name__ == '__main__':
    loop = True
    while loop:
        menu()
        choice = input("Enter your choice [1-3]: ")
        if choice == "1":
            url_file = input("URL List: ")
            with open(url_file) as fin:
                for l in fin:
                    get_url_report(l)
                    # Can be adjusted/removed if you have a private API key
                    sleep(15)
        elif choice == "2":
            hash_file = input("Hash List: ")
            with open(hash_file) as fin:
                for l in fin:
                    get_hash_report(l)
                    # Can be adjusted/removed if you have a private API key
                    sleep(15)
        elif choice == "3":
            system('clear')
            print("Exiting system...")
            sleep(2)
            loop = False
        else:
            input("Wrong option selection. Enter any key to try again..")
