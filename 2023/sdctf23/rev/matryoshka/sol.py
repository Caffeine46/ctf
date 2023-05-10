from pwn import *

M = 0x7fffffffffffee27
loop = 0x73b8e98d1b3879a2

d = pow(11, loop, M)
s = p64(0x888be665bfb73f2 * d % M).decode()

print(f'FLAG is sdctf{{{s}_{d}}}')