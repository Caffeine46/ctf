from z3 import *

MOD = 131
FLAG_LEN = 36
DOOR_SHAPE = [94, 68, 98, 110, 45, 81, 6, 76, 119, 53, 16, 19, 122, 91, 51, 44,
 13, 35, 2, 124, 83, 101, 75, 122, 75, 124, 37, 8, 127, 0, 22, 130,
 11, 42, 114, 19]
# DOOR_SHAPE = [69, 2, 68, 58, 94, 113, 62, 75, 0, 114, 22, 95, 92, 55, 13, 84, 112, 102, 90, 48, 47, 31, 98, 82, 100, 60, 111, 43, 34, 57, 77, 67, 51, 57, 26, 108]

def gencave(flaglen):
    cave = []
    ps = []
    i = 1
    while len(cave) <= flaglen:
        i += 1
        skip = False
        for p in ps:
            if i % p == 0:
                skip = True
                continue
        if skip:
            continue
        ps.append(i)
        if not cave:
            cave.append([])
        if len(cave[-1]) >= flaglen:
            cave.append([])
        cave[-1].append(i % MOD)

    cave = cave[:-1]
    return cave


def door(cave, word: str) -> bool:
    return word.isascii() and len(word) == FLAG_LEN or False
    code = list(magic_words.encode())
    m = magic(cave, code)
    return m == DOOR_SHAPE


def magic(a, b):
    return [URem(sum((a[i][j] * b[j] for j in range(FLAG_LEN))), MOD) for i in range(FLAG_LEN)]


if __name__ == '__main__':
    cave = gencave(FLAG_LEN)
    # print(cave)

    x = [BitVec("x%d" % i, 64) for i in range(36)]
    s = Solver()

    # m = magic(cave, x)
    # s.add(m == DOOR_SHAPE)

    for i in range(20):
        m = [cave[i][j] * x[j] for j in range(36)]
        s.add(sum(m) % MOD == DOOR_SHAPE[i])    

    r = s.check()
    print(r) # unsat...
    if r == sat:
        pf = s.model()
        print(pf)


    # print(f'cave len = {len(cave)}')
    # magic_words = input('Enter the magic words (the flag) to get the treasure (points): ')
    # print('You got the flag! Get the treasure by submitting it.' if door(cave, magic_words) else 'This is not the flag :(')