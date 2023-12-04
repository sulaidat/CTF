#!/usr/bin/env python3
from pwn import *
# helper
def byte2hex(byte_str):
    return int('0x' + byte_str[::-1].hex(), 16)

context.terminal = 'wt.exe sp -d . wsl.exe -d Ubuntu'.split()
context.arch = 'amd64'
host, port = 'nc host3.dreamhack.games 13646'.split()[1:]
port = int(port)
elf = ELF('./chal')
lib = ELF('./libc.so.6', checksec=False)

script = """
set follow-fork-mode parent 

brva 0x000000000002E78
brva 0x000000000002BBB
brva 0x000000000002DCB

c
"""

if args.REMOTE:
    p = remote(host, port)
elif args.GDB:
    p = gdb.debug(elf.path, gdbscript=script, aslr=False)
else:
    p = process(elf.path)

p.send(b'concac')

p.interactive()