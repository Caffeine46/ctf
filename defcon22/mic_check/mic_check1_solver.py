from concurrent.futures import process
import sys
from tkinter import E
from pwn import *

ticket = b"ticket{LeewardGull2577n22:pLXBQHUzcEuaG5RPiFlL2dj-1IKDyxeUBxkQsUnX7apTc-_w}"
io = remote("simple-service-c45xrrmhuc5su.shellweplayaga.me", 31337)

io.recvuntil(b": ")
io.sendline(ticket)

ret = io.recvuntil(b" ")
a = int(ret.decode())
print(a, end=' ')

ret = io.recvuntil(b"+ ")
print(ret.decode(), end=' ')

ret = io.recvuntil(b" ")
b = int(ret.decode())
print(b, end=' ')

ret = io.recvuntil(b"= ")
print(ret.decode(), end=' ')

ans = a + b
print(ans)
io.sendline(str(ans).encode())

io.interactive()