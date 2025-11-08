#!/usr/bin/env python3

import sys
from pwn import *

if len(sys.argv) != 2:
    print("Usage: python3 checker.py <TARGET_HOST>")
    sys.exit(1)

target = sys.argv[1]

def check_flag(c):
    c.sendline(b"giv_flag_pls")
    output = c.recvline(timeout=2).strip()
    success = b"FLAG_" in output
    if not success:
        raise Exception("Flag not found in response")

def attack1():
    c = remote(target, 4444)
    c.recvuntil(b">", timeout=2)
    c.sendline(b"AAAAAAAAAAAAAAAAAAAAAA/bin/sh")
    c.clean()
    check_flag(c)
    c.sendline(b"exit")
    c.close()

def attack2():
    c = remote(target, 4444)
    c.recvuntil(b">", timeout=2)
    c.sendline(b"normal-traffic")
    c.clean()
    c.sendline(b"now_with_hack?attack=SELECT * FROM flags LIMIT NONE")
    c.clean()
    check_flag(c)
    c.close()

def checker():
    c = remote(target, 4444)
    c.recvuntil(b">", timeout=2)
    c.sendline(b"normal-traffic")
    c.clean()
    check_flag(c)
    c.close()


def run():
    try:
        checker()
        print("Check successful")
    except Exception as e:
        print("Checker failed", e)
    try:
        attack1()
        print("Attack 1 successful")
    except Exception as e:
        print("Attack 1 failed", e)
    try:
        attack2()
        print("Attack 2 successful")
    except Exception as e:
        print("Attack 2 failed", e)

if __name__ == "__main__":
    run()