#!/usr/bin/env python
from __future__ import print_function
import sys
import struct
import hashlib

def pow_hash(challenge, solution):
    return hashlib.sha512(challenge + struct.pack('<Q', solution)).hexdigest()

def check_pow(challenge, n, solution):
    sol = solution
    h = pow_hash(challenge, sol)

    if h.startswith("0000"):
        return True

    return False

def solve_pow(challenge, n):
    candidate = 0
    
    while(True):
        if check_pow(challenge, n, candidate):
            return candidate
        candidate += 1

    return 0

def char2Nibble(c):
    c = ord(c)

    if(c >= ord('0') and c <= ord('9')):
        return c-ord('0')
    if(c >= ord('a') and c <= ord('f')):
        return c-ord('a')+0xa;
    if(c >= ord('A') and c <= ord('F')):
        return c-ord('A')+0xa;

    return 0;

if __name__ == '__main__':
    challenge = sys.argv[1]
    n = int(sys.argv[2])

    chal = ""

    for i in range(32):
        chal += chr((char2Nibble(challenge[i*2+0])<<4)|(char2Nibble(challenge[i*2+1])))
    
    solution = solve_pow(chal, n)
    solution = hex(solution)[4:6] + hex(solution)[2:4] + "000000000000"

    print(solution)
