from z3 import *

M = 0x10000

idx1 = [3, 1, 0, 6, 7, 4, 3, 1]
idx2 = [1, 0, 3, 2, 6, 7, 4, 5]
key = [0x85765e6f, 0x7b761fa8, 0x05306ec9, 0xbd5d8cfa, 0xc2db0af6, 0x6cf52153, 0xabec2bcd, 0x5c211278]

x = [BitVec("x%d" % i, 32) for i in range(8)]

s = Solver()

def chk1(x: list):
    l = []
    for i in range(8):
        l.append(x[i] >> 16)
        l.append(x[i] % M)
    s.add(sum(l) == 0x5dc44)

def chk2(x: list):
    l = []
    for i in range(8):
        l.append((x[i] + 0x419b) % M)
        l.append(((x[i] >> 16) + 0x419b) % M)
    
    p1 = []
    for i in idx1:
        p1.append(l[2*i])
        p1.append(l[2*i+1])

    p2 = []
    for i in idx2:
        p2.append(l[2*i])
        p2.append(l[2*i+1])
    
    ml = [(a * b) % M for a, b in zip(l, p2)]
    sb = [(a - b) % M for a, b in zip(ml, p1)]

    y = [sb[2*i+1] * M + sb[2*i] for i in range(8)]
    for i in range(len(y)):
        s.add(y[i] == key[i])

chk1(x)
chk2(x)

if s.check() == sat:
    m = s.model()
    c = [m[x[i]].as_long() for i in range(8)]
    flag = b""
    for i in range(7, -1, -1):
        flag += (c[i] >> 16).to_bytes(2, "little")
        flag += (c[i] & 0xffff).to_bytes(2, "little")
    print(flag)