from pwn import *
import sys

elf = ELF("vuln")
libc = ELF("libc.so.6")

io = process(elf.path, env = {"LD_PRELOAD":"./libc.so.6"})
# io = remote('generic-rop-challenge.chal.imaginaryctf.org', 42042)

context.arch = 'arm64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

gdb.attach(io)

io.interactive()