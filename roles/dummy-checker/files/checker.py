#!/usr/bin/env python3

import sys
from pwn import *

if len(sys.argv) != 2:
    print("Usage: python3 checker.py <TARGET_HOST>")
    sys.exit(1)

target = sys.argv[1]

def attack1():
    c = remote(target, 4444)
    c.recvuntil(b">", timeout=2)
    c.sendline(b"AAAAAAAAAAAAAAAAAAAAAA/bin/sh")
    c.clean()
    c.sendline(b"exit")
    c.close()

def attack2():
    c = remote(target, 4444)
    c.recvuntil(b">", timeout=2)
    c.sendline(b"normal-traffic")
    c.clean()
    c.sendline(b"now_with_hack?attack=SELECT * FROM flags LIMIT NONE")
    c.close()

def checker():
    c = remote(target, 4444)
    c.recvuntil(b">", timeout=2)
    c.sendline(b"normal-traffic")
    c.clean()
    c.sendline(b"giv_flag_pls")
    c.close()


def run():
    try:
        checker()
    except Exception as e:
        print("Checker failed", e)
    try:
        attack1()
    except Exception as e:
        print("Attack 1 failed", e)
    try:
        attack2()
    except Exception as e:
        print("Attack 2 failed", e)

if __name__ == "__main__":
    run()