import ast
import base64
import hashlib
import sys

def xor(*array: tuple[bytes], strict: bool = False) -> bytes:
    """XOR strings
    Calculate `A XOR B`.
    Args:
        A (bytes): A first string.
        B (bytes): A second string.
    Returns:
        bytes: The result of `A XOR B`.
    """

    if len(array) == 0:
        return None

    ret = bytes(len(array[0]))

    for block in array:
        ret = bytes(x ^ y for x, y in zip(ret, block))

    return ret

sys.setrecursionlimit(1000000)

with open("lock_decoded.txt", "r") as f:
    lock = f.read()

s = {"current": 1, "key": "", "t": lock, "idx": 0}
# fmt: off
C = bytes([62, 223, 233, 153, 37, 113, 79, 195, 9, 58, 83, 39, 245, 213, 253, 138, 225, 232, 123, 90, 8, 98, 105, 1, 31, 198, 67, 83, 41, 139, 118, 138, 252, 165, 214, 158, 116, 173, 174, 161, 6, 233, 37, 35, 86, 7, 108, 223, 97, 251, 2, 245, 129, 118, 227, 120, 26, 70, 40, 26, 183, 90, 172, 155])
# fmt: on


def hit_0():
    s["key"] += "0"
    s["t"] = s["t"][s["idx"]]
    s["idx"] = 0


def hit_1():
    s["key"] += "1"
    s["idx"] += 1


def submit_pin():
    s["idx"] = 0
    if s["t"] == s["current"]:
        if s["current"] == 1337:
            win()
        else:
            s["current"] += 1
            s["t"] = lock


def win(s):
    k = hashlib.sha512(s.encode()).digest()
    dec = xor(k, C)
    print(dec)

s = ""

for target in range(1, 1338):
    st = []
    current = ""
    for i, c in enumerate(lock):
        if c == "[":
            st.append(0)
            current = ""
        elif c == "]":
            if(current == str(target)):
                break
            current = ""
            st.pop()
        elif c == ",":
            if(current == str(target)):
                break
            current = ""
            st[-1] += 1
        elif c == " ":
           continue
        else:
            current += str(c) 


    b = ""
    for d in st:
        b += "1" * d
        b += "0"

    s += b

win(s)