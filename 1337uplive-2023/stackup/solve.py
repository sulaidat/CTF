#!/usr/bin/env python3
from pwn import *
# helper
def byte2hex(byte_str):
    return int('0x' + byte_str[::-1].hex(), 16)

context.terminal = 'wt.exe sp -d . wsl.exe -d Ubuntu'.split()
context.arch = 'amd64'
elf = ELF('./runtime')
# lib = ELF('./libc.so.6', checksec=False)

script = """
# brva 0x00000000000690B
brva 0x000000000006910
c
"""

# pc = f'./runtime ./cc'
pc = f'./runtime ./program.prg'
if args.REMOTE:
    p = remote('stackup.ctf.intigriti.io', 1337)
elif args.GDB:
    p = gdb.debug(pc.split(), gdbscript=script, aslr=False)
else:
    p = process(pc.split())




p.interactive()